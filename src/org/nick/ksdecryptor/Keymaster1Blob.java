
package org.nick.ksdecryptor;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Keymaster1Blob {

    private static final int INT_SIZE = 4;
    private static final int AES_BLOCK_SIZE = 16;

    private byte version;
    private byte[] keyMaterial;
    private AuthorizationSet hiddenAuthorizations;
    private AuthorizationSet enforcedAuthorizations;
    private AuthorizationSet unenforcedAuthorizations;

    private Keymaster1Blob() {
    }

    public static Keymaster1Blob parse(byte[] blob, SecretKey masterKey)
            throws GeneralSecurityException,
            InvalidCipherTextException {
        Keymaster1Blob result = new Keymaster1Blob();

        ByteBuffer bb = ByteBuffer.wrap(blob);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        int idx = 0;
        result.version = bb.get(idx);
        idx++;
        int nonceLength = bb.getInt(idx);
        idx += INT_SIZE;
        byte[] nonce = Arrays.copyOfRange(blob, idx, idx + nonceLength);
        idx = idx + nonceLength;
        int keyMaterialLength = bb.getInt(idx);
        idx += INT_SIZE;
        byte[] keyMaterial = Arrays.copyOfRange(blob, idx, idx + keyMaterialLength);
        idx = idx + keyMaterialLength;
        int tagLength = bb.getInt(idx);
        idx += INT_SIZE;
        byte[] tag = Arrays.copyOfRange(blob, idx, idx + tagLength);

        byte[] cipher = new byte[keyMaterial.length + tag.length];
        System.arraycopy(keyMaterial, 0, cipher, 0, keyMaterial.length);
        System.arraycopy(tag, 0, cipher, keyMaterial.length, tag.length);

        idx = idx + tagLength;
        // enforced + unenforced
        byte[] authorizations = Arrays.copyOfRange(blob, idx, blob.length);

        // hidden + enforced + unenforced
        byte[] dd = createDerivationData(authorizations);
        int off = 0;
        result.hiddenAuthorizations = AuthorizationSet.parse(dd, off);
        off += result.hiddenAuthorizations.getSerializedSize();
        result.enforcedAuthorizations = AuthorizationSet.parse(dd, off);
        off += result.enforcedAuthorizations.getSerializedSize();
        result.unenforcedAuthorizations = AuthorizationSet.parse(dd, off);

        SecretKey key = deriveKey(dd, masterKey);

        KeyParameter keyParameter = new KeyParameter(key.getEncoded());
        int macLengthBits = tagLength * 8;
        AEADParameters parameters = new AEADParameters(keyParameter,
                macLengthBits, nonce);

        AEADBlockCipher ocbCipher = createOCBCipher(false, parameters);
        byte[] decrypted = new byte[ocbCipher.getOutputSize(cipher.length)];
        int len = ocbCipher.processBytes(cipher, 0, cipher.length, decrypted, 0);
        len += ocbCipher.doFinal(decrypted, len);
        byte[] mac = ocbCipher.getMac();
        if (!Arrays.equals(tag, mac)) {
            throw new IllegalStateException("MAC doesn't match. Corrupt blob?");
        }
        result.keyMaterial = decrypted;

        return result;
    }

    private static SecretKey deriveKey(byte[] dd, SecretKey masterKey)
            throws GeneralSecurityException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA256");
        byte[] digest = sha256.digest(dd);

        Cipher aesEcb = Cipher.getInstance("AES/ECB/NoPadding");
        aesEcb.init(Cipher.ENCRYPT_MODE, masterKey);
        byte[] encryptedKey = aesEcb.doFinal(digest);

        return new SecretKeySpec(Arrays.copyOf(encryptedKey, AES_BLOCK_SIZE), "AES");
    }

    // hidden + enforced + unenforced
    private static byte[] createDerivationData(byte[] authorizations) {
        int hiddenSize = 6 * INT_SIZE + 2;
        byte[] dd = new byte[authorizations.length + hiddenSize];
        AuthorizationSet.generateSwRootOfTrust(dd);
        System.arraycopy(authorizations, 0, dd, hiddenSize, authorizations.length);

        return dd;
    }

    private static AEADBlockCipher createOCBCipher(boolean forEncryption, AEADParameters parameters) {
        AEADBlockCipher c = new OCBBlockCipher(new AESEngine(), new AESEngine());
        c.init(forEncryption, parameters);

        return c;
    }

    public byte getVersion() {
        return version;
    }

    public byte[] getKeyMaterial() {
        return keyMaterial == null ? null : keyMaterial.clone();
    }

    public AuthorizationSet getHiddenAuthorizations() {
        return hiddenAuthorizations;
    }

    public AuthorizationSet getEnforcedAuthorizations() {
        return enforcedAuthorizations;
    }

    public AuthorizationSet getUnenforcedAuthorizations() {
        return unenforcedAuthorizations;
    }

    public void dumpAuthorizations() {
        System.out.println("Hidden tags:");
        hiddenAuthorizations.dumpTags();
        System.out.println();

        System.out.println("Enforced tags:");
        enforcedAuthorizations.dumpTags();
        System.out.println();

        System.out.println("Unenforced tags:");
        unenforcedAuthorizations.dumpTags();
        System.out.println();
    }

    public int getKeySize() {
        if (enforcedAuthorizations.containsTag(AuthorizationSet.TAG_KEY_SIZE)) {
            return enforcedAuthorizations.getKeySize();
        }

        return unenforcedAuthorizations.getKeySize();
    }

    public String getKeyAlgorithm() {
        if (enforcedAuthorizations.containsTag(AuthorizationSet.TAG_ALGORITHM)) {
            return enforcedAuthorizations.getKeyAlgorithm();
        }

        return unenforcedAuthorizations.getKeyAlgorithm();
    }

}
