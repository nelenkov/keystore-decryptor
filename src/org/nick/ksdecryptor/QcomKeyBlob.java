
package org.nick.ksdecryptor;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

//#define KM_MAGIC_NUM     (0x4B4D4B42)    /* "KMKB" Key Master Key Blob in hex */
//#define KM_KEY_SIZE_MAX  (512)           /* 4096 bits */
//#define KM_IV_LENGTH     (16)            /* AES128 CBC IV */
//#define KM_HMAC_LENGTH   (32)            /* SHA2 will be used for HMAC  */
//
//struct  qcom_km_key_blob {
//  uint32_t magic_num;
//  uint32_t version_num;
//  uint8_t  modulus[KM_KEY_SIZE_MAX];
//  uint32_t modulus_size;
//  uint8_t  public_exponent[KM_KEY_SIZE_MAX];
//  uint32_t public_exponent_size;
//  uint8_t  iv[KM_IV_LENGTH];
//  uint8_t  encrypted_private_exponent[KM_KEY_SIZE_MAX];
//  uint32_t encrypted_private_exponent_size;
//  uint8_t  hmac[KM_HMAC_LENGTH];
//};
public class QcomKeyBlob {

    private static final int INT_SIZE = 4;

    public static final int KM_MAGIC_NUM = 0x4B4D4B42;
    private static final int KM_KEY_SIZE_MAX = 512; /* 4096 bits */
    private static final int KM_IV_LENGTH = 16; /* AES128 CBC IV */
    private static final int KM_HMAC_LENGTH = 32; /* SHA2 will be used for HMAC */

    private int magic;
    private int version;
    private BigInteger modulus;
    private BigInteger publicExponent;
    private byte[] iv;
    private byte[] encryptedPrivateExponent;
    private byte[] hmac;

    private QcomKeyBlob() {
    }

    public static QcomKeyBlob parse(byte[] blob) {
        QcomKeyBlob result = new QcomKeyBlob();

        ByteBuffer bb = ByteBuffer.wrap(blob);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        int idx = 0;
        result.magic = bb.getInt();
        if (result.magic != KM_MAGIC_NUM) {
            throw new IllegalStateException("Unexpected magic: " + result.magic);
        }
        idx += INT_SIZE;
        result.version = bb.getInt();
        idx += INT_SIZE;
        int modulusIdx = idx;
        idx += KM_KEY_SIZE_MAX;
        int modulusSize = bb.getInt(idx);
        idx += INT_SIZE;
        byte[] modulusBytes = Arrays.copyOfRange(blob, modulusIdx, modulusIdx + modulusSize);
        result.modulus = new BigInteger(1, modulusBytes);
        int pubExpIdx = idx;
        idx += KM_KEY_SIZE_MAX;
        int pubExpSize = bb.getInt(idx);
        idx += INT_SIZE;
        byte[] pubExpBytes = Arrays.copyOfRange(blob, pubExpIdx, pubExpIdx + pubExpSize);
        result.publicExponent = new BigInteger(pubExpBytes);
        result.iv = Arrays.copyOfRange(blob, idx, idx + KM_IV_LENGTH);
        idx += KM_IV_LENGTH;
        int privExpIdx = idx;
        idx += KM_KEY_SIZE_MAX;
        int privExpSize = bb.getInt(idx);
        idx += INT_SIZE;
        result.encryptedPrivateExponent = Arrays.copyOfRange(blob, privExpIdx, privExpIdx
                + privExpSize);
        result.hmac = Arrays.copyOfRange(blob, idx, idx + KM_HMAC_LENGTH);

        return result;
    }

    public int getMagic() {
        return magic;
    }

    public int getVersion() {
        return version;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    public byte[] getIv() {
        return iv == null ? null : iv.clone();
    }

    public byte[] getEncryptedPrivateExponent() {
        return encryptedPrivateExponent == null ? encryptedPrivateExponent : null;
    }

    public byte[] getHmac() {
        return hmac == null ? null : hmac.clone();
    }

    @Override
    public String toString() {
        StringBuilder buff = new StringBuilder();
        buff.append("QCom key blob:\n");
        buff.append(String.format("  magic:    0x%08X\n", magic));
        buff.append(String.format("  version:  %d\n", version));
        buff.append(String.format("  modulus:  %s... (%d bits)\n",
                modulus.toString(16).substring(0, 32),
                modulus.bitLength()));
        buff.append(String.format("  pub exp:  0x%s\n",
                publicExponent.toString(16)));
        buff.append(String.format("  priv exp: %s... (encr.)\n",
                Hex.toHexString(encryptedPrivateExponent).substring(0, 32)));

        return buff.toString();
    }
}
