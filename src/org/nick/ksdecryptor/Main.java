
package org.nick.ksdecryptor;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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
        KeystoreBlob masterKeyBlob = KeystoreBlob.parseMasterKey(mkBlob, password);
        showBlob(masterKeyBlob);
        SecretKey masterKey = new SecretKeySpec(masterKeyBlob.getValue(), "AES");

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
        X509Certificate cert = parseCert(ksBlob.getValue());
        System.out.println("X509Certificate:");
        System.out.println("  issuer: " + cert.getIssuerDN());
        System.out.println("  subject: " + cert.getSubjectDN());
        System.out.println("  serial: " + cert.getSerialNumber());
        System.out.println();
    }

    private static void showKeyPair(KeystoreBlob ksBlob) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(ksBlob.getValue());
        bb.order(ByteOrder.LITTLE_ENDIAN);
        int magic = bb.getInt();
        if (magic == QcomKeyBlob.KM_MAGIC_NUM) {
            QcomKeyBlob qcKeyBlob = QcomKeyBlob.parse(ksBlob.getValue());
            System.out.println(qcKeyBlob.toString());
            System.out.println();
        } else {
            // most probably an EC key
            try {
                showEcKey(ksBlob);
            } catch (IOException e) {
                System.out.println("Unknown key pair format");
            }
        }
    }

    private static void showEcKey(KeystoreBlob ksBlob) throws GeneralSecurityException,
            IOException, InvalidCipherTextException {
        Keymaster1Blob km1b = Keymaster1Blob.parse(ksBlob.getValue(), ZERO_KEY);
        ASN1InputStream ain = new ASN1InputStream(new ByteArrayInputStream(
                km1b.getKeyMaterial()));
        ECPrivateKey pk = ECPrivateKey.getInstance(ain.readObject());
        ain.close();

        System.out.println("EC key:");
        System.out.printf("  s: %s (%d)\n",
                pk.getKey().toString(16).substring(0, 32),
                pk.getKey().bitLength());
        System.out.printf("  params: %s\n", pk.getParameters());
        System.out.printf("  key size: %d\n", km1b.getKeySize());
        System.out.printf("  key algorithm: %s\n", km1b.getKeyAlgorithm());
        System.out.printf("  authorizations:\n");
        km1b.dumpAuthorizations();
        System.out.println();
    }

    private static void showMasterKey(KeystoreBlob ksBlob) {
        System.out.println("master key: " + Hex.toHexString(ksBlob.getValue()));
        System.out.println();
    }

    private static void showKeyMaterial(KeystoreBlob ksBlob) throws Exception {
        Keymaster1Blob km1b = Keymaster1Blob.parse(ksBlob.getValue(), ZERO_KEY);
        System.out.println("Keymaster v1 blob:");
        System.out.printf("  key size: %d\n", km1b.getKeySize());
        System.out.printf("  key algorithm: %s\n", km1b.getKeyAlgorithm());
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

        return result;
    }

    private static void writeBlob(byte[] blob, String filename) throws IOException {
        FileOutputStream fos = new FileOutputStream(
                filename);
        fos.write(blob);
        fos.flush();
        fos.close();
    }

    private static X509Certificate parseCert(byte[] certBytes) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }

}
