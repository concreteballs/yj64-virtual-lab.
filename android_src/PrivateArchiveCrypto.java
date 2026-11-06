package org.blackmirror.blackmirror;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

/** Portable password-based AES-GCM encryption for private YJ-64 archives. */
public final class PrivateArchiveCrypto {
    private static final byte[] MAGIC = "YJ64P01\n".getBytes(StandardCharsets.US_ASCII);
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int ITERATIONS = 310000;
    private static final int TAG_BITS = 128;
    private static final long MAX_FILE_BYTES = 128L * 1024L * 1024L;

    private PrivateArchiveCrypto() {}

    private static byte[] readFile(File file) throws Exception {
        if (!file.isFile() || file.length() <= 0 || file.length() > MAX_FILE_BYTES + 128) {
            throw new IllegalArgumentException("Archive file size is invalid.");
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try (java.io.FileInputStream in = new java.io.FileInputStream(file)) {
            byte[] chunk = new byte[8192];
            int count;
            while ((count = in.read(chunk)) != -1) out.write(chunk, 0, count);
        }
        return out.toByteArray();
    }

    private static void writeBytes(File file, byte[] data) throws Exception {
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(file)) {
            out.write(data);
            out.flush();
            out.getFD().sync();
        }
    }

    public static long copyStream(java.io.InputStream input, java.io.OutputStream output) throws Exception {
        byte[] buffer = new byte[8192];
        long copied = 0;
        int count;
        while ((count = input.read(buffer)) != -1) {
            output.write(buffer, 0, count);
            copied += count;
        }
        output.flush();
        return copied;
    }

    private static SecretKey derive(char[] password, byte[] salt) throws Exception {
        ByteBuffer encodedPassword = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] passwordBytes = new byte[encodedPassword.remaining()];
        encodedPassword.get(passwordBytes);
        byte[] block = new byte[salt.length + 4];
        System.arraycopy(salt, 0, block, 0, salt.length);
        block[block.length - 1] = 1;
        byte[] u = null;
        byte[] key = new byte[32];
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(passwordBytes, "HmacSHA256"));
            u = mac.doFinal(block);
            System.arraycopy(u, 0, key, 0, key.length);
            for (int round = 1; round < ITERATIONS; round++) {
                byte[] next = mac.doFinal(u);
                java.util.Arrays.fill(u, (byte) 0);
                u = next;
                for (int i = 0; i < key.length; i++) key[i] ^= u[i];
            }
            return new SecretKeySpec(key, "AES");
        } finally {
            java.util.Arrays.fill(passwordBytes, (byte) 0);
            if (encodedPassword.hasArray()) java.util.Arrays.fill(encodedPassword.array(), (byte) 0);
            java.util.Arrays.fill(block, (byte) 0);
            if (u != null) java.util.Arrays.fill(u, (byte) 0);
            java.util.Arrays.fill(key, (byte) 0);
        }
    }

    public static String encryptFile(String inputPath, String outputPath, String password) throws Exception {
        if (password == null || password.length() < 12) throw new IllegalArgumentException("Use a passphrase of at least 12 characters.");
        byte[] plain = readFile(new File(inputPath));
        if (plain.length == 0 || plain.length > MAX_FILE_BYTES) throw new IllegalArgumentException("Private archive size is outside the supported limit.");
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);
        char[] chars = password.toCharArray();
        byte[] encrypted;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, derive(chars, salt), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(MAGIC);
            encrypted = cipher.doFinal(plain);
        } finally {
            java.util.Arrays.fill(chars, '\0');
            java.util.Arrays.fill(plain, (byte) 0);
        }
        ByteBuffer buffer = ByteBuffer.allocate(MAGIC.length + 4 + SALT_BYTES + IV_BYTES + encrypted.length);
        buffer.put(MAGIC).putInt(ITERATIONS).put(salt).put(iv).put(encrypted);
        File output = new File(outputPath);
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) throw new java.io.IOException("Cannot create output directory.");
        File temporary = new File(outputPath + ".tmp");
        try {
            writeBytes(temporary, buffer.array());
            if (output.exists() && !output.delete()) throw new java.io.IOException("Cannot replace encrypted archive.");
            if (!temporary.renameTo(output)) throw new java.io.IOException("Cannot finalize encrypted archive.");
        } finally {
            if (temporary.exists()) temporary.delete();
            java.util.Arrays.fill(encrypted, (byte) 0);
            java.util.Arrays.fill(buffer.array(), (byte) 0);
        }
        return output.getAbsolutePath();
    }

    public static String decryptFile(String inputPath, String outputPath, String password) throws Exception {
        if (password == null || password.length() < 1) throw new IllegalArgumentException("Passphrase is required.");
        byte[] encoded = readFile(new File(inputPath));
        if (encoded.length < MAGIC.length + 4 + SALT_BYTES + IV_BYTES + 16 || encoded.length > MAX_FILE_BYTES + 128) {
            throw new IllegalArgumentException("Encrypted archive has an invalid size.");
        }
        byte[] plain = null;
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            byte[] magic = new byte[MAGIC.length];
            buffer.get(magic);
            if (!java.util.Arrays.equals(magic, MAGIC)) throw new IllegalArgumentException("This is not a YJ-64 encrypted private archive.");
            int iterations = buffer.getInt();
            if (iterations != ITERATIONS) throw new IllegalArgumentException("Unsupported archive key-derivation version.");
            byte[] salt = new byte[SALT_BYTES];
            byte[] iv = new byte[IV_BYTES];
            buffer.get(salt).get(iv);
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);
            char[] chars = password.toCharArray();
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, derive(chars, salt), new GCMParameterSpec(TAG_BITS, iv));
                cipher.updateAAD(MAGIC);
                plain = cipher.doFinal(ciphertext);
            } finally {
                java.util.Arrays.fill(chars, '\0');
                java.util.Arrays.fill(ciphertext, (byte) 0);
            }
            if (plain.length == 0 || plain.length > MAX_FILE_BYTES) throw new IllegalArgumentException("Decrypted archive size is invalid.");
            File output = new File(outputPath);
            File parent = output.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) throw new java.io.IOException("Cannot create output directory.");
            File temporary = new File(outputPath + ".tmp");
            try {
                writeBytes(temporary, plain);
                if (output.exists() && !output.delete()) throw new java.io.IOException("Cannot replace temporary archive.");
                if (!temporary.renameTo(output)) throw new java.io.IOException("Cannot finalize decrypted archive.");
            } finally {
                if (temporary.exists()) temporary.delete();
            }
            return output.getAbsolutePath();
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
            if (plain != null) java.util.Arrays.fill(plain, (byte) 0);
        }
    }
}
