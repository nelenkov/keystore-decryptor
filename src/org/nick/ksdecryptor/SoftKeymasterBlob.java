
package org.nick.ksdecryptor;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class SoftKeymasterBlob {

    // 'PK#8'
    public static final int SOFT_KM_MAGIC = 0x504b2338;
    public static final int SOFT_KM_MAGIC_LE = 0x38234b50;

    // from OpenSSL
    public static final int EVP_PKEY_RSA = 6;
    public static final int EVP_PKEY_DSA = 116;
    public static final int EVP_PKEY_EC = 408;

    private static final ASN1ObjectIdentifier secp224r1_OID = new ASN1ObjectIdentifier(
            "1.3.132.0.33");
    private static final ASN1ObjectIdentifier prime256v1_OID = new ASN1ObjectIdentifier(
            "1.2.840.10045.3.1.7");
    private static final ASN1ObjectIdentifier secp384r1_OID = new ASN1ObjectIdentifier(
            "1.3.132.0.34");
    private static final ASN1ObjectIdentifier secp521r1_OID = new ASN1ObjectIdentifier(
            "1.3.132.0.35");

    private static final int INT_SIZE = 4;

    private int type;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private SoftKeymasterBlob() {
    }

    public static SoftKeymasterBlob parse(byte[] blob) {
        try {
            SoftKeymasterBlob result = new SoftKeymasterBlob();
            ByteBuffer bb = ByteBuffer.wrap(blob);
            bb.order(ByteOrder.BIG_ENDIAN);

            int idx = 0;
            int magic = bb.getInt(0);
            if (magic != SOFT_KM_MAGIC) {
                throw new IllegalStateException(
                        String.format("Invalid soft KM blob? Magic=%08X", magic));
            }

            idx += INT_SIZE;
            int type = bb.getInt(idx);
            idx += INT_SIZE;
            int pubKeyLen = 0;
            if (type != EVP_PKEY_EC && type != EVP_PKEY_DSA && type != EVP_PKEY_RSA) {
                // could be a 4.3 blob, which has no type, always RSA
                pubKeyLen = type;
                type = EVP_PKEY_RSA;
            } else {
                pubKeyLen = bb.getInt(idx);
                idx += INT_SIZE;
            }
            result.type = type;
            if (pubKeyLen > 0) {
                @SuppressWarnings("unused")
                byte[] pubKeyBytes = Arrays.copyOfRange(blob, idx, idx + pubKeyLen);
                // XXX try to parse? in practice always empty?
            }
            idx += pubKeyLen;
            int privKeyLen = bb.getInt(idx);
            idx += INT_SIZE;
            byte[] privKeyBytes = Arrays.copyOfRange(blob, idx, idx + privKeyLen);
            result.parsePrivateKey(privKeyBytes);

            return result;
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void parsePrivateKey(byte[] privKeyBytes)
            throws GeneralSecurityException,
            IOException, InvalidCipherTextException {
        if (type == EVP_PKEY_EC) {
            privateKey = parseEcKey(privKeyBytes);
            publicKey = null;
        } else if (type == EVP_PKEY_DSA) {
            parseDsaKeyPair(privKeyBytes);
        } else if (type == EVP_PKEY_RSA) {
            parseRsaKeyPair(privKeyBytes);
        } else {
            throw new IllegalStateException("Unknown soft KM blob type: " + type);
        }
    }

    private void parseDsaKeyPair(byte[] blob) throws GeneralSecurityException,
            IOException {
        ASN1InputStream ain = new ASN1InputStream(new ByteArrayInputStream(
                blob));
        ASN1Sequence seq = (ASN1Sequence) ain.readObject();
        ain.close();

        ASN1Integer p = (ASN1Integer) seq.getObjectAt(1);
        ASN1Integer q = (ASN1Integer) seq.getObjectAt(2);
        ASN1Integer g = (ASN1Integer) seq.getObjectAt(3);
        ASN1Integer y = (ASN1Integer) seq.getObjectAt(4);
        ASN1Integer x = (ASN1Integer) seq.getObjectAt(5);
        DSAPrivateKeySpec privSpec = new DSAPrivateKeySpec(x.getValue(), p.getValue(),
                q.getValue(), g.getValue());
        DSAPublicKeySpec pubSpec = new DSAPublicKeySpec(y.getValue(), p.getValue(), q.getValue(),
                g.getValue());

        KeyFactory kf = KeyFactory.getInstance("DSA");
        privateKey = kf.generatePrivate(privSpec);
        publicKey = kf.generatePublic(pubSpec);
    }

    public static ECPrivateKey parseEcKey(byte[] blob) throws GeneralSecurityException,
            IOException, InvalidCipherTextException {
        ASN1InputStream ain = new ASN1InputStream(new ByteArrayInputStream(
                blob));
        org.bouncycastle.asn1.sec.ECPrivateKey pk = org.bouncycastle.asn1.sec.ECPrivateKey
                .getInstance(ain.readObject());
        ain.close();

        return toJcaPrivateKey(pk);
    }

    private static ECPrivateKey toJcaPrivateKey(org.bouncycastle.asn1.sec.ECPrivateKey ecPrivateKey)
            throws GeneralSecurityException {
        String curveName = null;
        ASN1ObjectIdentifier curveId = (ASN1ObjectIdentifier) ecPrivateKey.getParameters();
        if (curveId.equals(secp224r1_OID)) {
            curveName = "secp224r1";
        } else if (curveId.equals(prime256v1_OID)) {
            curveName = "prime256v1";
        } else if (curveId.equals(secp384r1_OID)) {
            curveName = "secp384r1";
        } else if (curveId.equals(secp521r1_OID)) {
            curveName = "secp521r1";
        } else {
            throw new IllegalStateException("Unknown curve OID: " + curveId);
        }

        ECNamedCurveParameterSpec sp = ECNamedCurveTable.getParameterSpec(curveName);
        ECParameterSpec params = new ECNamedCurveSpec(sp.getName(), sp.getCurve(), sp.getG(),
                sp.getN(), sp.getH());

        ECPrivateKeySpec pkSpec = new ECPrivateKeySpec(ecPrivateKey.getKey(), params);
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(pkSpec);

        return privateKey;
    }

    public void parseRsaKeyPair(byte[] b) throws GeneralSecurityException, IOException {
        ASN1InputStream ain = new ASN1InputStream(new ByteArrayInputStream(b));
        ASN1Sequence seq = (ASN1Sequence) ain.readObject();
        ain.close();

        org.bouncycastle.asn1.pkcs.RSAPrivateKey pk = org.bouncycastle.asn1.pkcs.RSAPrivateKey
                .getInstance(seq);
        privateKey = toJcaPrivateKey(pk);
        publicKey = toJcaPublicKey(pk);
    }

    public static RSAPrivateKey parseRsaKey(byte[] b) throws GeneralSecurityException, IOException {
        ASN1InputStream ain = new ASN1InputStream(new ByteArrayInputStream(b));
        ASN1Sequence seq = (ASN1Sequence) ain.readObject();
        ain.close();
        for (int i = 0; i < seq.size(); i++) {
            ASN1Integer p = (ASN1Integer) seq.getObjectAt(i);
            System.out.printf("%d::%s\n", i, p.toString());
        }

        org.bouncycastle.asn1.pkcs.RSAPrivateKey pk = org.bouncycastle.asn1.pkcs.RSAPrivateKey
                .getInstance(seq);
        return toJcaPrivateKey(pk);
    }

    private static RSAPrivateKey toJcaPrivateKey(
            org.bouncycastle.asn1.pkcs.RSAPrivateKey rsaPrivateKey)
            throws GeneralSecurityException {
        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(rsaPrivateKey.getModulus(),
                                                             rsaPrivateKey.getPublicExponent(),
                                                             rsaPrivateKey.getPrivateExponent(),
                                                             rsaPrivateKey.getPrime1(),
                                                             rsaPrivateKey.getPrime2(),
                                                             rsaPrivateKey.getExponent1(),
                                                             rsaPrivateKey.getExponent2(),
                                                             rsaPrivateKey.getCoefficient());
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(spec);

        return privateKey;
    }

    private static RSAPublicKey toJcaPublicKey(
            org.bouncycastle.asn1.pkcs.RSAPrivateKey rsaPrivateKey)
            throws GeneralSecurityException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(),
                rsaPrivateKey.getPublicExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(spec);

        return publicKey;
    }

    public int getType() {
        return type;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

}
