
package org.nick.ksdecryptor;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private static final SecretKey ZERO_KEY = new SecretKeySpec(new byte[16], "AES");

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: ksdecryptor <master key file>  <key file>  <password>");
            System.exit(1);
        }

        String mkFile = args[0];
        String keyBlobFile = args[1];
        String password = args[2];

        byte[] mkBlob = readBlob(mkFile);
        KeystoreBlob masterKeyBlob = KeystoreBlob.parseMasterKey(mkBlob,
                password);
        showBlob(masterKeyBlob);
        SecretKey masterKey = masterKeyBlob.getMasterKey();

        byte[] blob = readBlob(keyBlobFile);
        KeystoreBlob keyBlob = KeystoreBlob.parse(blob, masterKey);
        showBlob(keyBlob);
    }

    private static void showBlob(KeystoreBlob ksBlob) throws Exception {
        byte type = ksBlob.getType();
        switch (type) {
            case KeystoreBlob.KEY_BLOB_TYPE_GENERIC:
                showCert(ksBlob);
                break;
            case KeystoreBlob.KEY_BLOB_TYPE_KEY_PAIR:
                showKeyPair(ksBlob);
                break;
            case KeystoreBlob.KEY_BLOB_TYPE_MASTER_KEY:
                showMasterKey(ksBlob);
                break;
            case KeystoreBlob.KEY_BLOB_TYPE_KEYMASTER_10:
                showKeyMaterial(ksBlob);
                break;
            default:
                throw new IllegalStateException("Uknown key blob type: " + type);
        }
    }

    private static void showCert(KeystoreBlob ksBlob) throws GeneralSecurityException {
        X509Certificate cert = ksBlob.getCertificate();
        System.out.println("X509Certificate:");
        System.out.println("  issuer: " + cert.getIssuerDN());
        System.out.println("  subject: " + cert.getSubjectDN());
        System.out.println("  serial: " + cert.getSerialNumber());
        System.out.println();
    }

    private static void showKeyPair(KeystoreBlob ksBlob) throws Exception {
        try {
            byte[] blob = ksBlob.getValue();
            ByteBuffer bb = ByteBuffer.wrap(ksBlob.getValue());
            bb.order(ByteOrder.LITTLE_ENDIAN);
            int magic = bb.getInt();
            if (magic == QcomKeyBlob.KM_MAGIC_NUM) {
                QcomKeyBlob qcKeyBlob = QcomKeyBlob.parse(ksBlob.getValue());
                System.out.println(qcKeyBlob.toString());
                System.out.println();
            } else if (magic == SoftKeymasterBlob.SOFT_KM_MAGIC_LE) {
                SoftKeymasterBlob softKmBlob = SoftKeymasterBlob
                        .parse(blob);
                showJcaPrivateKey(softKmBlob.getPrivateKey());
            } else {
                // most probably keymaster v1 RSA or EC key
                Keymaster1Blob km1b = Keymaster1Blob.parse(ksBlob.getValue(), ZERO_KEY);
                PrivateKey pk = km1b.getPrivateKey();
                showJcaPrivateKey(pk);
                System.out.printf("key size: %d\n", km1b.getKeySize());
                System.out.printf("key algorithm: %s\n", km1b.getKeyAlgorithm());
                km1b.dumpAuthorizations();
            }
        } catch (Exception e) {
            System.out.println("Unknown key pair format");
            e.printStackTrace();
        }
    }

    private static void showJcaPrivateKey(PrivateKey pk) {
        if (pk instanceof RSAPrivateKey) {
            RSAPrivateKey rsaPrivKey = (RSAPrivateKey) pk;
            System.out.printf("RSA private exponent: %s (%d)\n",
                    rsaPrivKey.getPrivateExponent().toString(16).substring(0, 32), rsaPrivKey
                            .getPrivateExponent().bitLength());
            System.out.printf("RSA modulus: %s... (%d)\n", rsaPrivKey.getModulus().toString(16)
                    .substring(0, 32),
                    rsaPrivKey.getModulus().bitLength());
        } else if (pk instanceof java.security.interfaces.ECPrivateKey) {
            java.security.interfaces.ECPrivateKey ecPrivKey = (java.security.interfaces.ECPrivateKey) pk;
            System.out.printf("EC S: %s... (%d)\n",
                    ecPrivKey.getS().toString(16).substring(0, 32),
                    ecPrivKey.getS().bitLength());
            if (ecPrivKey.getParams() instanceof ECNamedCurveSpec) {
                ECNamedCurveSpec namedCurveSpec = (ECNamedCurveSpec) ecPrivKey.getParams();
                System.out.println("curve name: " + namedCurveSpec.getName());
            } else {
                System.out.println("EC params: " + ecPrivKey.getParams());
            }
        } else if (pk instanceof DSAPrivateKey) {
            DSAPrivateKey dsaPrivKey = (DSAPrivateKey) pk;
            System.out.printf("DSA X: %s... (%d)\n",
                    dsaPrivKey.getX().toString(16).substring(0, 32), dsaPrivKey.getX()
                            .bitLength());
            System.out.println("DSA params: " + dsaPrivKey.getParams());
        } else {
            System.out.println("Unknown private key type: " + pk.getClass().getName());
        }
    }

    private static void showMasterKey(KeystoreBlob ksBlob) {
        System.out.println("master key: " + Hex.toHexString(ksBlob.getMasterKey().getEncoded()));
        System.out.println();
    }

    private static void showKeyMaterial(KeystoreBlob ksBlob) {
        Keymaster1Blob km1b = Keymaster1Blob.parse(ksBlob.getValue(), ZERO_KEY);
        System.out.println("Keymaster v1 blob:");
        System.out.printf("  key size: %d\n", km1b.getKeySize());
        System.out.printf("  key algorithm: %s\n", km1b.getKeyAlgorithmName());
        System.out.println("  key material: " + Hex.toHexString(km1b.getKeyMaterial()));
        System.out.println("  authorizations:\n");
        km1b.dumpAuthorizations();
        System.out.println();
    }

    private static byte[] readBlob(String filename) throws IOException {
        FileInputStream fis = new FileInputStream(filename);
        byte[] result = new byte[fis.available()];
        fis.read(result);
        fis.close();

        File f = new File(filename);
        System.out.printf("Read '%s'\n", f.getName());

        return result;
    }

    private static void writeBlob(byte[] blob, String filename) throws IOException {
        FileOutputStream fos = new FileOutputStream(
                filename);
        fos.write(blob);
        fos.flush();
        fos.close();
    }

}
