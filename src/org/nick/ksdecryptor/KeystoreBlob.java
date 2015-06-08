
package org.nick.ksdecryptor;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

//struct __attribute__((packed)) blob {
// uint8_t version;
// uint8_t type;
// uint8_t flags;
// uint8_t info;
// uint8_t vector[AES_BLOCK_SIZE];
// uint8_t encrypted[0]; // Marks offset to encrypted data.
// uint8_t digest[MD5_DIGEST_LENGTH];
// uint8_t digested[0]; // Marks offset to digested data.
// int32_t length; // in network byte order when encrypted
// uint8_t value[VALUE_SIZE + AES_BLOCK_SIZE];
// };
public class KeystoreBlob {

    public static final int KEY_BLOB_TYPE_ANY = 0; // meta type that matches
                                                   // anything
    public static final int KEY_BLOB_TYPE_GENERIC = 1;
    public static final int KEY_BLOB_TYPE_MASTER_KEY = 2;
    public static final int KEY_BLOB_TYPE_KEY_PAIR = 3;
    public static final int KEY_BLOB_TYPE_KEYMASTER_10 = 4;

    public static final int KEYSTORE_FLAG_NONE = 0;
    public static final int KEYSTORE_FLAG_ENCRYPTED = 1 << 0;
    public static int KEYSTORE_FLAG_FALLBACK = 1 << 1;

    private static final int AES_BLOCK_SIZE = 128 / 8;

    private static final int SALT_SIZE = 16;
    private static final int MD5_DIGEST_LENGTH = 16;

    private static final int KEK_DERIVATION_ITERRACTION_COUNT = 8192;
    private static final int KEK_LENGTH = 128;

    private byte version;
    private byte type;
    private byte flags;
    private byte info;

    private byte[] decrypted;
    private int length;
    private byte[] value;
    private byte[] description;

    private KeystoreBlob() {
    }

    public static KeystoreBlob parseMasterKey(byte[] blob, String password) {
        try {
            KeystoreBlob result = new KeystoreBlob();

            int idx = 0;
            result.version = blob[idx++];
            result.type = blob[idx++];
            result.flags = blob[idx++];
            result.info = blob[idx++];

            byte[] iv = Arrays.copyOfRange(blob, idx, idx + AES_BLOCK_SIZE);
            idx = idx + AES_BLOCK_SIZE;

            byte[] encrypted = Arrays.copyOfRange(blob, idx, blob.length - result.info);

            byte[] salt = Arrays.copyOfRange(blob, blob.length - SALT_SIZE, blob.length);
            SecretKey kek = generateKek(password, salt);
            result.decrypted = decrypt(iv, encrypted, kek);

            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digested = Arrays.copyOfRange(result.decrypted, MD5_DIGEST_LENGTH,
                    result.decrypted.length);
            byte[] calcMd5 = md.digest(digested);

            idx = 0;
            byte[] digest = Arrays.copyOfRange(result.decrypted, idx, idx + MD5_DIGEST_LENGTH);
            if (!Arrays.equals(calcMd5, digest)) {
                // throw new
                // IllegalStateException("Digest doesn't match. Invalid key blob?");
            }

            idx = idx + MD5_DIGEST_LENGTH;
            result.length = readInt(result.decrypted, idx);

            idx = idx + 4;
            result.value = Arrays.copyOfRange(result.decrypted, idx, idx + result.length);

            idx = idx + result.length;
            result.description = Arrays.copyOfRange(result.decrypted, idx, idx + result.info);

            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeystoreBlob parse(byte[] blob, SecretKey masterKey) {
        try {
            KeystoreBlob result = new KeystoreBlob();

            int idx = 0;
            result.version = blob[idx++];
            result.type = blob[idx++];
            result.flags = blob[idx++];
            result.info = blob[idx++];

            byte[] iv = Arrays.copyOfRange(blob, idx, idx + AES_BLOCK_SIZE);
            idx = idx + AES_BLOCK_SIZE;

            byte[] encrypted = Arrays.copyOfRange(blob, idx, blob.length - result.info);

            if (result.isEncrypted()) {
                result.decrypted = decrypt(iv, encrypted, masterKey);

                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] digested = Arrays.copyOfRange(result.decrypted, MD5_DIGEST_LENGTH,
                        result.decrypted.length);
                byte[] calcMd5 = md.digest(digested);

                idx = 0;
                byte[] digest = Arrays.copyOfRange(result.decrypted, idx, idx + MD5_DIGEST_LENGTH);
                if (!Arrays.equals(calcMd5, digest)) {
                    throw new IllegalStateException("Digest doesn't match. Invalid key blob?");
                }
            } else {
                result.decrypted = encrypted;
                idx = 0;
            }

            idx = idx + MD5_DIGEST_LENGTH;
            result.length = readInt(result.decrypted, idx);

            idx = idx + 4;
            result.value = Arrays.copyOfRange(result.decrypted, idx, idx + result.length);

            idx = idx + result.length;
            result.description = Arrays.copyOfRange(result.decrypted, idx, idx + result.info);

            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static int readInt(byte[] data, int idx) {
        return (data[idx] << 24) | (data[idx + 1] << 16)
                | (data[idx + 2] << 8) | (0xff & data[idx + 3]);
    }

    private static byte[] decrypt(byte[] iv, byte[] encrypted, SecretKey kek)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        c.init(Cipher.DECRYPT_MODE, kek, ivSpec);

        return c.doFinal(encrypted);
    }

    private static SecretKey generateKek(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                KEK_DERIVATION_ITERRACTION_COUNT, KEK_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = keyFactory.generateSecret(keySpec);

        // avoid exceptions due to overzealous key type checks
        return new SecretKeySpec(key.getEncoded(), "AES");
    }

    public byte getVersion() {
        return version;
    }

    public byte getType() {
        return type;
    }

    public String getTypeString() {
        switch (type) {
            case KEY_BLOB_TYPE_GENERIC:
                return "generic";
            case KEY_BLOB_TYPE_MASTER_KEY:
                return "master key";
            case KEY_BLOB_TYPE_KEY_PAIR:
                return "key pair";
            case KEY_BLOB_TYPE_KEYMASTER_10:
                return "keymaster v1.0";
            default:
                throw new IllegalStateException("Unknown blob type: " + type);
        }
    }

    public byte getFlags() {
        return flags;
    }

    public byte getInfo() {
        return info;
    }

    public byte[] getDecrypted() {
        return decrypted == null ? null : decrypted.clone();
    }

    public int getLength() {
        return length;
    }

    public byte[] getValue() {
        return value == null ? null : value.clone();
    }

    public byte[] getDescription() {
        return description == null ? null : description.clone();
    }

    public boolean isEncrypted() {
        return (flags & KEYSTORE_FLAG_ENCRYPTED) == KEYSTORE_FLAG_ENCRYPTED;
    }

    public SecretKey getMasterKey() {
        if (type != KEY_BLOB_TYPE_MASTER_KEY || value.length != AES_BLOCK_SIZE) {
            throw new IllegalStateException("Not a master key blob, type is :" + type);
        }

        return new SecretKeySpec(getValue(), "AES");
    }

    private static X509Certificate parseCert(byte[] certBytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public X509Certificate getCertificate() {
        if (type != KEY_BLOB_TYPE_GENERIC) {
            throw new IllegalStateException("Not a certificate blob, type is :" + type);
        }

        return parseCert(getValue());
    }

}
