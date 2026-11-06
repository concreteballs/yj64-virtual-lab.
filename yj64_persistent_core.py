"""Persistent event ledger and verified cumulative YJ-64 archive."""
from __future__ import annotations
import hashlib, json, os, re, shutil, sqlite3, time, uuid, zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from diagnostics import sanitize_event_data

class PersistentCore:
    ARCHIVE_SCHEMA = "yj64.archive.v2"
    SECRET_KEYS = {"private_messages","api_key","api_keys","token","access_token","refresh_token","authorization"}
    def __init__(self,user_data_dir:str|Path):
        self.root=Path(user_data_dir);self.root.mkdir(parents=True,exist_ok=True)
        self.db_path=self.root/"yj64-persistent-core.sqlite3";self.workspace_path=self.root/"yj64-workspace"
        self.report_path=self.root/"yj64-reports"/"yj64-report.jsonl";self.archive_state_path=self.root/"yj64-archive-state.zip"
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ms INTEGER NOT NULL, event TEXT NOT NULL, data_json TEXT NOT NULL)")
        self._sanitize_existing_events()
    def _connect(self):
        db=sqlite3.connect(str(self.db_path),timeout=5);db.execute("PRAGMA journal_mode=WAL");return db
    def record_event(self,event:str,data:dict[str,Any]|None=None)->None:
        safe_data = sanitize_event_data(event, data or {})
        try:
            with self._connect() as db:
                db.execute(
                    "INSERT INTO events(timestamp_ms,event,data_json) VALUES(?,?,?)",
                    (int(time.time()*1000), str(event), json.dumps(safe_data, ensure_ascii=False)),
                )
        except sqlite3.Error:
            return

    def _sanitize_existing_events(self) -> None:
        """Remove legacy raw message/error payloads from the local event ledger."""
        try:
            with self._connect() as db:
                rows = db.execute("SELECT id,event,data_json FROM events").fetchall()
                for row_id, event, raw_json in rows:
                    try:
                        raw_data = json.loads(raw_json)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        raw_data = {}
                    safe_data = sanitize_event_data(str(event), raw_data if isinstance(raw_data, dict) else {})
                    safe_json = json.dumps(safe_data, ensure_ascii=False)
                    if safe_json != raw_json:
                        db.execute("UPDATE events SET data_json=? WHERE id=?", (safe_json, row_id))
        except sqlite3.Error:
            return
    @staticmethod
    def _sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()
    @staticmethod
    def _safe_name(name:str)->bool:
        p=PurePosixPath(name);return bool(name) and not p.is_absolute() and all(x not in ("",".","..") for x in p.parts) and "\\" not in name
    @classmethod
    def _sanitize(cls,value:Any)->Any:
        if isinstance(value,dict):return {k:cls._sanitize(v) for k,v in value.items() if str(k).lower() not in cls.SECRET_KEYS}
        if isinstance(value,list):return [cls._sanitize(x) for x in value]
        return value
    @classmethod
    def _sanitize_json(cls,payload:bytes)->bytes:
        try:data=json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError,json.JSONDecodeError):return payload
        return json.dumps(cls._sanitize(data),ensure_ascii=False,indent=2).encode("utf-8")
    def _collect_files(self)->dict[str,bytes]:
        result={}
        # Diagnostic JSONL can contain legacy sensitive records; never place it
        # in a common archive, even if older versions wrote raw payloads there.
        for base in (self.workspace_path,):
            if base.is_file() and not base.is_symlink():items=[base]
            elif base.is_dir() and not base.is_symlink():items=[p for p in base.rglob("*") if p.is_file() and not p.is_symlink()]
            else:items=[]
            for p in items:
                name=p.relative_to(self.root).as_posix()
                if name.startswith("yj64-workspace/histories/"):
                    continue
                if p.suffix.lower() == ".jsonl":
                    continue
                data=p.read_bytes()
                result[name]=self._sanitize_json(data) if p.suffix.lower()==".json" else data
        for pattern in ("yj64-router-config.json","yj64-llm-config*.json"):
            for p in self.root.glob(pattern):
                if p.is_file() and not p.is_symlink():result[p.name]=self._sanitize_json(p.read_bytes())
        return result
    @staticmethod
    def _merge_history(old:bytes,new:bytes)->bytes:
        try:a=json.loads(old.decode("utf-8"));b=json.loads(new.decode("utf-8"))
        except (UnicodeDecodeError,json.JSONDecodeError):return new
        if not isinstance(a,list) or not isinstance(b,list):return new
        merged={}
        for item in a+b:
            if not isinstance(item,dict):continue
            mid=str(item.get("message_id") or "legacy:"+hashlib.sha256(json.dumps(item,sort_keys=True,ensure_ascii=False).encode()).hexdigest());merged[mid]=item
        rows=list(merged.values());rows.sort(key=lambda x:(x.get("timestamp",x.get("timestamp_ms",0)) or 0,str(x.get("message_id",""))))
        return json.dumps(rows,ensure_ascii=False,indent=2).encode("utf-8")
    def _read_previous(self):
        if not self.archive_state_path.is_file() or not zipfile.is_zipfile(self.archive_state_path):return {},None
        try:
            with zipfile.ZipFile(self.archive_state_path) as z:
                if z.testzip():return {},None
                m=json.loads(z.read("manifest.json").decode("utf-8"))
                if m.get("schema")!=self.ARCHIVE_SCHEMA:return {},None
                return {n:z.read(n) for n in m.get("files",{})},m
        except (OSError,KeyError,ValueError,zipfile.BadZipFile,json.JSONDecodeError):return {},None
    @staticmethod
    def _safe_archive_stem(value: str) -> str:
        stem = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value)).strip("_-")
        return stem[:64] or "participant"

    def export_private_archives(self, destination: str | Path) -> list[Path]:
        """Export one verified, separate ZIP per participant; never include these files in common ZIPs."""
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)
        workspace = self.workspace_path
        histories = workspace / "histories"
        agents = workspace / "agents"
        grouped: dict[str, dict[str, Any]] = {}

        if histories.is_dir():
            for path in sorted(histories.glob("*.json")):
                if not path.is_file() or path.is_symlink():
                    continue
                participant = path.stem
                try:
                    rows = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise IOError(f"Private history cannot be read: {path.name}: {exc}") from exc
                if not isinstance(rows, list) or not all(isinstance(x, dict) for x in rows):
                    raise IOError(f"Private history has invalid format: {path.name}")
                grouped.setdefault(participant, {"histories": {}, "agents": []})
                grouped[participant]["histories"][path.name] = rows

        if agents.is_dir():
            for path in sorted(agents.glob("*.json")):
                if not path.is_file() or path.is_symlink():
                    continue
                try:
                    agent = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise IOError(f"Agent record cannot be read: {path.name}: {exc}") from exc
                if not isinstance(agent, dict):
                    raise IOError(f"Agent record has invalid format: {path.name}")
                private = agent.get("private_messages", [])
                if not isinstance(private, list):
                    raise IOError(f"Agent private_messages has invalid format: {path.name}")
                if not private:
                    continue
                participant = "".join(ch for ch in str(agent.get("runner") or "owner") if ch.isalnum() or ch in "-_ ").strip().replace(" ", "_") or "participant"
                grouped.setdefault(participant, {"histories": {}, "agents": []})
                grouped[participant]["agents"].append({
                    "agent_id": str(agent.get("id") or path.stem),
                    "name": str(agent.get("name") or ""),
                    "runner": str(agent.get("runner") or ""),
                    "created_ms": agent.get("created_ms"),
                    "private_messages": private,
                })

        results: list[Path] = []
        for participant, payload in sorted(grouped.items()):
            participant_hash = hashlib.sha256(participant.encode("utf-8")).hexdigest()[:12]
            archive_path = destination / ("YJ64_private_" + self._safe_archive_stem(participant) + "_" + participant_hash + ".zip")
            members = {
                "private-data.json": json.dumps(
                    {"schema": "yj64.private-chat.v1", "participant_id": participant,
                     "histories": payload["histories"], "agents": payload["agents"]},
                    ensure_ascii=False, indent=2,
                ).encode("utf-8")
            }
            manifest = {
                "schema": "yj64.private-archive.v1",
                "participant_id": participant,
                "created_at_ms": int(time.time() * 1000),
                "files": {name: {"sha256": self._sha(data), "size": len(data)}
                          for name, data in sorted(members.items())},
            }
            temporary = archive_path.with_suffix(".zip.tmp")
            try:
                with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as z:
                    for name, data in sorted(members.items()):
                        z.writestr(name, data)
                    z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
                if not zipfile.is_zipfile(temporary):
                    raise IOError("Private archive is not a ZIP file")
                with zipfile.ZipFile(temporary, "r") as z:
                    if z.testzip() or len(z.namelist()) != len(set(z.namelist())):
                        raise IOError("Private archive integrity check failed")
                    if set(z.namelist()) != set(members) | {"manifest.json"}:
                        raise IOError("Private archive member list mismatch")
                    checked = json.loads(z.read("manifest.json").decode("utf-8"))
                    for name, meta in checked.get("files", {}).items():
                        data = z.read(name)
                        if len(data) != int(meta.get("size", -1)) or self._sha(data) != meta.get("sha256"):
                            raise IOError("Private archive SHA-256 mismatch: " + name)
                os.replace(temporary, archive_path)
                if not archive_path.is_file() or archive_path.stat().st_size <= 0:
                    raise IOError("Private archive output is empty")
                results.append(archive_path)
            except Exception:
                temporary.unlink(missing_ok=True)
                raise
        return results

    def export_private_bundle(self, destination: str | Path) -> Path:
        """Package participant-private ZIPs into one verified bundle for encryption."""
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        work = destination.parent / (destination.name + ".parts")
        work.mkdir(parents=True, exist_ok=True)
        archives = []
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        try:
            archives = self.export_private_archives(work)
            members = {
                "participants/" + path.name: path.read_bytes()
                for path in archives
            }
            if not members:
                raise ValueError("No participant-private data is available to export")
            manifest = {
                "schema": "yj64.private-bundle.v1",
                "created_at_ms": int(time.time() * 1000),
                "files": {
                    name: {"sha256": self._sha(data), "size": len(data)}
                    for name, data in sorted(members.items())
                },
            }
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in sorted(members.items()):
                    archive.writestr(name, data)
                archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
            with zipfile.ZipFile(temporary, "r") as check:
                if check.testzip() or set(check.namelist()) != set(members) | {"manifest.json"}:
                    raise IOError("Private bundle integrity check failed")
                verified = json.loads(check.read("manifest.json").decode("utf-8"))
                if verified.get("schema") != "yj64.private-bundle.v1":
                    raise IOError("Private bundle schema mismatch")
                for name, meta in verified.get("files", {}).items():
                    data = check.read(name)
                    if len(data) != int(meta.get("size", -1)) or self._sha(data) != meta.get("sha256"):
                        raise IOError("Private bundle SHA-256 mismatch: " + name)
            os.replace(temporary, destination)
            return destination
        finally:
            temporary.unlink(missing_ok=True)
            for path in archives:
                path.unlink(missing_ok=True)
            for path in work.glob("*.zip"):
                path.unlink(missing_ok=True)
            try:
                work.rmdir()
            except OSError:
                pass

    def import_private_bundle(self, source: str | Path) -> int:
        """Validate and restore all participant-private histories from a decrypted bundle."""
        source = Path(source)
        if not source.is_file() or not zipfile.is_zipfile(source):
            raise ValueError("Decrypted private bundle is not a valid ZIP archive")
        staged_data: dict[str, bytes] = {}
        with zipfile.ZipFile(source, "r") as bundle:
            names = bundle.namelist()
            if bundle.testzip() or len(names) != len(set(names)) or names.count("manifest.json") != 1:
                raise ValueError("Private bundle integrity/manifest check failed")
            manifest = json.loads(bundle.read("manifest.json").decode("utf-8"))
            if not isinstance(manifest, dict) or manifest.get("schema") != "yj64.private-bundle.v1":
                raise ValueError("Unsupported private bundle schema")
            declared = manifest.get("files")
            if not isinstance(declared, dict) or set(names) != set(declared) | {"manifest.json"}:
                raise ValueError("Private bundle file list mismatch")
            for member, meta in declared.items():
                if not isinstance(member, str) or not member.startswith("participants/") or not member.endswith(".zip"):
                    raise ValueError("Unsafe private bundle member")
                if not self._safe_name(member) or member.count("/") != 1:
                    raise ValueError("Unsafe private bundle path")
                nested = bundle.read(member)
                if len(nested) != int(meta.get("size", -1)) or self._sha(nested) != meta.get("sha256"):
                    raise ValueError("Private bundle SHA-256 mismatch: " + member)
                import io
                with zipfile.ZipFile(io.BytesIO(nested), "r") as participant_zip:
                    participant_names = participant_zip.namelist()
                    if participant_zip.testzip() or len(participant_names) != len(set(participant_names)):
                        raise ValueError("Participant archive integrity check failed")
                    if set(participant_names) != {"private-data.json", "manifest.json"}:
                        raise ValueError("Participant archive members are invalid")
                    inner_manifest = json.loads(participant_zip.read("manifest.json").decode("utf-8"))
                    if not isinstance(inner_manifest, dict) or inner_manifest.get("schema") != "yj64.private-archive.v1":
                        raise ValueError("Unsupported participant archive schema")
                    private_json = participant_zip.read("private-data.json")
                    inner_files = inner_manifest.get("files")
                    if not isinstance(inner_files, dict) or set(inner_files) != {"private-data.json"}:
                        raise ValueError("Participant archive manifest is invalid")
                    inner_meta = inner_files["private-data.json"]
                    if len(private_json) != int(inner_meta.get("size", -1)) or self._sha(private_json) != inner_meta.get("sha256"):
                        raise ValueError("Participant archive SHA-256 mismatch")
                    data = json.loads(private_json.decode("utf-8"))
                    if not isinstance(data, dict) or data.get("schema") != "yj64.private-chat.v1":
                        raise ValueError("Invalid participant private data")
                    participant = self._safe_archive_stem(data.get("participant_id") or "")
                    if participant != self._safe_archive_stem(inner_manifest.get("participant_id") or ""):
                        raise ValueError("Participant identity mismatch")
                    histories = data.get("histories", {})
                    agents = data.get("agents", [])
                    if not isinstance(histories, dict) or not isinstance(agents, list):
                        raise ValueError("Invalid participant history structure")
                    for filename, rows in histories.items():
                        if not isinstance(filename, str) or Path(filename).name != filename or "\\" in filename or not filename.endswith(".json"):
                            raise ValueError("Unsafe private history filename")
                        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                            raise ValueError("Invalid private history rows")
                        staged_data["yj64-workspace/histories/" + filename] = json.dumps(
                            rows, ensure_ascii=False, indent=2
                        ).encode("utf-8")
                    for agent in agents:
                        if not isinstance(agent, dict) or not isinstance(agent.get("private_messages"), list):
                            raise ValueError("Invalid private agent record")
                        agent_id = re.sub(r"[^A-Za-z0-9_-]", "", str(agent.get("agent_id") or ""))
                        if not agent_id:
                            raise ValueError("Invalid private agent identifier")
                        record = {
                            "id": agent_id,
                            "name": str(agent.get("name") or ""),
                            "runner": str(agent.get("runner") or participant),
                            "created_ms": agent.get("created_ms"),
                            "private_messages": agent["private_messages"],
                        }
                        staged_data["yj64-workspace/agents/" + agent_id + ".json"] = json.dumps(
                            record, ensure_ascii=False, indent=2
                        ).encode("utf-8")
        staged = []
        committed = []
        try:
            for relative, data in staged_data.items():
                target = self.root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name(target.name + ".private-restore-tmp")
                temporary.write_bytes(data)
                backup = target.read_bytes() if target.is_file() else None
                staged.append((target, temporary, backup))
            for target, temporary, backup in staged:
                os.replace(temporary, target)
                committed.append((target, backup))
        except Exception:
            for target, backup in reversed(committed):
                if backup is None:
                    target.unlink(missing_ok=True)
                else:
                    rollback = target.with_name(target.name + ".private-rollback-tmp")
                    rollback.write_bytes(backup)
                    os.replace(rollback, target)
            raise
        finally:
            for _, temporary, _ in staged:
                temporary.unlink(missing_ok=True)
        return len(staged_data)

    def export_archive(self,destination:str|Path)->Path:
        dest=Path(destination);dest.parent.mkdir(parents=True,exist_ok=True);tmp=dest.with_suffix(dest.suffix+".tmp");state_tmp=self.archive_state_path.with_suffix(".zip.tmp")
        previous,old_manifest=self._read_previous();merged=dict(previous);current=self._collect_files()
        # Remove any legacy private histories previously accumulated in a common archive.
        for name in list(merged):
            if name.startswith("yj64-workspace/histories/"):
                del merged[name]
        for name,data in current.items():
            if name.startswith("yj64-workspace/chats/") and name.endswith(".json") and name in merged:data=self._merge_history(merged[name],data)
            merged[name]=data
        idx="yj64-workspace/chats.json"
        if idx not in merged:raise IOError("Archive cannot be created: chat index missing")
        try:index=json.loads(merged[idx].decode("utf-8"));chats=index.get("chats",[]) if isinstance(index,dict) else []
        except (UnicodeDecodeError,json.JSONDecodeError,AttributeError) as exc:raise IOError("Invalid archive chat index") from exc
        if not isinstance(chats,list) or not chats:raise IOError("Archive has no saved chats")
        for item in chats:
            cid=re.sub(r"[^A-Za-z0-9_-]","",str(item.get("id",""))) if isinstance(item,dict) else ""
            if not cid or f"yj64-workspace/chats/{cid}.json" not in merged:raise IOError("Saved chat history missing")
        try:
            with self._connect() as db:events=db.execute("SELECT timestamp_ms,event,data_json FROM events ORDER BY id").fetchall()
            merged["yj64-events-export.json"]=json.dumps(events,ensure_ascii=False).encode("utf-8")
        except sqlite3.Error:pass
        messages=[]
        for name,data in merged.items():
            if name.startswith("yj64-workspace/chats/") and name.endswith(".json"):
                rows=json.loads(data.decode("utf-8"))
                if isinstance(rows,list):messages.extend(x for x in rows if isinstance(x,dict))
        messages.sort(key=lambda x:x.get("timestamp",x.get("timestamp_ms",0)) or 0);now=int(time.time()*1000)
        manifest={"schema":self.ARCHIVE_SCHEMA,"archive_id":(old_manifest or {}).get("archive_id") or uuid.uuid4().hex,
          "created_at":(old_manifest or {}).get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(now/1000)),
          "updated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(now/1000)),
          "last_message_id":str(messages[-1].get("message_id","")) if messages else None,"message_count":len(messages),
          "included":["common_chat_history","workspace_metadata","local_skills","router_model_settings_without_secrets","technical_diagnostics"],
          "excluded":["participant_private_messages","api_keys_and_tokens","application_private_database"],
          "files":{n:{"sha256":self._sha(d),"size":len(d)} for n,d in sorted(merged.items())}}
        try:
            for target in (tmp,state_tmp):
                with zipfile.ZipFile(target,"w",compression=zipfile.ZIP_DEFLATED) as z:
                    for n,d in sorted(merged.items()):z.writestr(n,d)
                    z.writestr("manifest.json",json.dumps(manifest,ensure_ascii=False,indent=2))
                self._verify_archive(target)
            os.replace(state_tmp,self.archive_state_path);os.replace(tmp,dest)
        except Exception:tmp.unlink(missing_ok=True);state_tmp.unlink(missing_ok=True);raise
        return dest
    def _verify_archive(self,path:Path):
        if not path.is_file() or path.stat().st_size<=0 or not zipfile.is_zipfile(path):raise IOError("Archive ZIP empty or invalid")
        with zipfile.ZipFile(path) as z:
            names=z.namelist()
            if z.testzip() or len(names)!=len(set(names)) or names.count("manifest.json")!=1:raise IOError("Archive integrity/manifest check failed")
            m=json.loads(z.read("manifest.json").decode("utf-8"))
            if m.get("schema")!=self.ARCHIVE_SCHEMA or not isinstance(m.get("files"),dict):raise IOError("Unsupported archive manifest")
            for n,meta in m["files"].items():
                if not self._safe_name(n) or n not in names:raise IOError("Unsafe or missing archive path")
                data=z.read(n)
                if len(data)!=int(meta.get("size",-1)) or self._sha(data)!=meta.get("sha256"):raise IOError("Archive SHA-256/size mismatch: "+n)
            if set(names)!=set(m["files"])|{"manifest.json"}:raise IOError("Undeclared archive files")
            return m
    def import_archive(self,source:str|Path)->int:
        source=Path(source)
        if not source.is_file() or not zipfile.is_zipfile(source):raise ValueError("Not a valid ZIP archive")
        with zipfile.ZipFile(source) as z:
            names=z.namelist()
            if z.testzip() or len(names)!=len(set(names)) or names.count("manifest.json")!=1:raise ValueError("Archive integrity/manifest check failed")
            m=json.loads(z.read("manifest.json").decode("utf-8"));schema=m.get("schema") if isinstance(m,dict) else None
            if schema not in ("yj64.archive.v1",self.ARCHIVE_SCHEMA):raise ValueError("Unsupported archive schema")
            declared=m.get("files")
            if schema==self.ARCHIVE_SCHEMA:
                if not isinstance(declared,dict):raise ValueError("Invalid hash manifest")
                payloads={}
                for n,meta in declared.items():
                    if not self._safe_name(n) or n not in names:raise ValueError("Unsafe/missing archive path")
                    data=z.read(n)
                    if len(data)!=int(meta.get("size",-1)) or self._sha(data)!=meta.get("sha256"):raise ValueError("Archive SHA-256/size mismatch: "+n)
                    payloads[n]=data
                if set(names)!=set(payloads)|{"manifest.json"}:raise ValueError("Undeclared archive files")
            else:
                if not isinstance(declared,list) or not all(isinstance(n,str) and self._safe_name(n) for n in declared):raise ValueError("Invalid legacy manifest")
                payloads={n:z.read(n) for n in declared if n in names}
                if set(payloads)!=set(declared):raise ValueError("Legacy archive contents mismatch")
        idx="yj64-workspace/chats.json"
        if idx not in payloads:raise ValueError("Archive chat index missing")
        index=json.loads(payloads[idx].decode("utf-8"));chats=index.get("chats",[]) if isinstance(index,dict) else []
        if not isinstance(chats,list) or not chats:raise ValueError("Archive has no saved chats")
        for item in chats:
            cid=re.sub(r"[^A-Za-z0-9_-]","",str(item.get("id",""))) if isinstance(item,dict) else "";h=f"yj64-workspace/chats/{cid}.json"
            if not cid or h not in payloads:raise ValueError("Archive chat history missing")
            rows=json.loads(payloads[h].decode("utf-8"))
            if not isinstance(rows,list) or not all(isinstance(x,dict) and "role" in x and "content" in x for x in rows):raise ValueError("Invalid chat history")
        staged=[];allowed_root={"yj64-router-config.json"}
        try:
            for n,data in payloads.items():
                allowed=n.startswith(("yj64-workspace/","yj64-reports/")) or n in allowed_root or (n.startswith("yj64-llm-config-") and n.endswith(".json"))
                if not allowed:continue
                target=self.root/n;target.parent.mkdir(parents=True,exist_ok=True);stage=target.with_name(target.name+".restore-tmp");stage.write_bytes(data)
                backup=target.read_bytes() if target.is_file() else None;staged.append((target,stage,backup))
            committed=[]
            try:
                for target,stage,backup in staged:os.replace(stage,target);committed.append((target,backup))
            except Exception:
                for target,backup in reversed(committed):
                    if backup is None:target.unlink(missing_ok=True)
                    else:
                        rollback=target.with_name(target.name+".rollback-tmp");rollback.write_bytes(backup);os.replace(rollback,target)
                raise
        finally:
            for _,stage,_ in staged:stage.unlink(missing_ok=True)
        if schema==self.ARCHIVE_SCHEMA:
            state_tmp=self.archive_state_path.with_suffix(".zip.tmp");shutil.copyfile(source,state_tmp);os.replace(state_tmp,self.archive_state_path)
        return len(staged)
