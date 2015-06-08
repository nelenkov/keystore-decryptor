
package org.nick.ksdecryptor;

import org.bouncycastle.util.encoders.Hex;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class AuthorizationSet {

    private static final int INT_SIZE = 4;
    private static final int LONG_SIZE = 8;

    // Invalid type, used to designate a tag as uninitialized
    private static final int KM_INVALID = 0 << 28;
    private static final int KM_ENUM = 1 << 28;
    // Repeatable enumeration value.
    private static final int KM_ENUM_REP = 2 << 28;
    private static final int KM_INT = 3 << 28;
    // Repeatable integer value
    private static final int KM_INT_REP = 4 << 28;
    private static final int KM_LONG = 5 << 28;
    private static final int KM_DATE = 6 << 28;
    private static final int KM_BOOL = 7 << 28;
    private static final int KM_BIGNUM = 8 << 28;
    private static final int KM_BYTES = 9 << 28;
    // Repeatable long value
    private static final int KM_LONG_REP = 10 << 28;

    public static final int TAG_PURPOSE = KM_ENUM_REP | 1;
    public static final int TAG_ALGORITHM = KM_ENUM | 2;
    public static final int TAG_KEY_SIZE = KM_INT | 3;
    public static final int TAG_BLOCK_MODE = KM_ENUM_REP | 4;
    public static final int TAG_DIGEST = KM_ENUM_REP | 5;
    public static final int TAG_PADDING = KM_ENUM_REP | 6;

    private static final int TAG_ROOT_OF_TRUST = KM_BYTES | 704;

    public static final int ALGORITHM_RSA = 1;
    public static final int ALGORITHM_EC = 3;
    public static final int ALGORITHM_AES = 32;
    public static final int ALGORITHM_HMAC = 128;

    private int indirectDataSize;
    private byte[] indirectData;
    private int elementsCount;
    private int elementsSize;

    private int serializedSize;

    private Map<Integer, Object> tags = new HashMap<Integer, Object>();

    private AuthorizationSet() {
    }

    public static AuthorizationSet parse(byte[] blob, int offset) {
        AuthorizationSet result = new AuthorizationSet();

        int j = offset;
        ByteBuffer bb = ByteBuffer.wrap(blob, offset, blob.length - offset);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        result.indirectDataSize = bb.getInt(j);
        j += INT_SIZE;
        if (result.indirectDataSize > 0) {
            result.indirectData = Arrays.copyOfRange(blob, j, j + result.indirectDataSize);
        }
        j += result.indirectDataSize;
        int elementsCount = bb.getInt(j);
        result.elementsCount = elementsCount;
        j += INT_SIZE;
        int elementsSize = bb.getInt(j);
        result.elementsSize = elementsSize;
        j += INT_SIZE;

        for (int i = 0; i < elementsCount; i++) {
            int tag = bb.getInt(j);
            j += INT_SIZE;
            int tagType = (tag & (0xF << 28));
            switch (tagType) {
                case KM_INVALID:
                    break;
                case KM_ENUM:
                    int ti = bb.getInt(j);
                    j += INT_SIZE;
                    result.tags.put(tag, ti);
                    break;
                case KM_ENUM_REP:
                    ti = bb.getInt(j);
                    j += INT_SIZE;
                    result.tags.put(tag, ti);
                    break;
                case KM_INT:
                    ti = bb.getInt(j);
                    j += INT_SIZE;
                    result.tags.put(tag, ti);
                    break;
                case KM_INT_REP:
                    ti = bb.getInt(j);
                    j += INT_SIZE;
                    result.tags.put(tag, ti);
                    break;
                case KM_LONG:
                    long tl = bb.getLong(j);
                    j += LONG_SIZE;
                    result.tags.put(tag, tl);
                    break;
                case KM_LONG_REP:
                    tl = bb.getLong(j);
                    j += LONG_SIZE;
                    result.tags.put(tag, tl);
                    break;
                case KM_DATE:
                    tl = bb.getLong(j);
                    j += LONG_SIZE;
                    result.tags.put(tag, tl);
                    break;
                case KM_BOOL:
                    byte tb = bb.get(j);
                    j++;
                    result.tags.put(tag, tb);
                    break;
                case KM_BIGNUM:
                    int len = bb.getInt(j);
                    j += INT_SIZE;
                    int off = bb.getInt(j);
                    j += INT_SIZE;
                    byte[] bytes = Arrays.copyOfRange(result.indirectData, off, off + len);
                    j += len;
                    result.tags.put(tag, bytes);
                    break;
                case KM_BYTES:
                    len = bb.getInt(j);
                    j += INT_SIZE;
                    off = bb.getInt(j);
                    j += INT_SIZE;
                    bytes = Arrays.copyOfRange(result.indirectData, off, off + len);
                    result.tags.put(tag, bytes);
                    break;

                default:
                    throw new IllegalStateException("Invalid tag type: " + tagType);
            }
        }

        result.serializedSize = j - offset;

        return result;
    }

    public int getElementsCount() {
        return elementsCount;
    }

    public int getIndirectDataSize() {
        return indirectDataSize;
    }

    public byte[] getIndirectData() {
        return indirectData;
    }

    public int getElementsSize() {
        return elementsSize;
    }

    public Map<Integer, Object> getTags() {
        return tags;
    }

    public int getSerializedSize() {
        return serializedSize;
    }

    public void dumpTags() {
        for (Integer tag : tags.keySet()) {
            System.out.printf("tag=%08X ", tag);
            Object value = tags.get(tag);
            int tagType = (tag & (0xF << 28));
            switch (tagType) {
                case KM_INVALID:
                    System.out.print("TAG_KM_INVALID ");
                    break;
                case KM_ENUM:
                    System.out.print("TAG_KM_ENUM ");
                    System.out.printf("%08X\n", (Integer) value);
                    break;
                case KM_ENUM_REP:
                    System.out.print("TAG_KM_ENUM_REP ");
                    System.out.printf("%08X\n", (Integer) value);
                    break;
                case KM_INT:
                    System.out.print("TAG_KM_INT ");
                    System.out.printf("%08X\n", (Integer) value);
                    break;
                case KM_INT_REP:
                    System.out.print("TAG_KM_INT_REP ");
                    System.out.printf("%08X\n", (Integer) value);
                    break;
                case KM_LONG:
                    System.out.print("TAG_KM_LONG ");
                    System.out.printf("%016X\n", (Long) value);
                    break;
                case KM_LONG_REP:
                    System.out.print("TAG_KM_LONG_REP ");
                    System.out.printf("%016X\n", (Long) value);
                    break;
                case KM_DATE:
                    System.out.print("TAG_KM_DATE ");
                    System.out.printf("%016X: %s\n", (Long) value,
                            new Date((Long) value).toString());
                    break;
                case KM_BOOL:
                    System.out.print("TAG_KM_BOOL ");
                    System.out.printf("%X\n", (Byte) value);
                    break;
                case KM_BIGNUM:
                    System.out.print("TAG_KM_BIGNUM ");
                    byte[] bytes = (byte[]) value;
                    System.out.printf("bytes: %s (%d)\n", Hex.toHexString(bytes), bytes.length);
                    break;
                case KM_BYTES:
                    System.out.print("TAG_KM_BYTES ");
                    bytes = (byte[]) value;
                    System.out.printf("bytes: %s (%d)\n", Hex.toHexString(bytes), bytes.length);
                    break;

                default:
                    throw new IllegalStateException("Invalid tag type: " + tagType);
            }
        }
    }

    public static void generateSwRootOfTrust(byte[] dd) {
        ByteBuffer ddBb = ByteBuffer.wrap(dd);
        ddBb.order(ByteOrder.LITTLE_ENDIAN);
        // indirect data size
        ddBb.putInt(2);
        // indirect data
        ddBb.put((byte) 'S');
        ddBb.put((byte) 'W');
        // num elements
        ddBb.putInt(1);
        // elements size
        ddBb.putInt(3 * INT_SIZE);
        // tag
        ddBb.putInt(TAG_ROOT_OF_TRUST);
        // data_length
        ddBb.putInt(2);
        // indirect data offset
        ddBb.putInt(0);
    }

    public boolean containsTag(int tag) {
        return tags.containsKey(tag);
    }

    public int getKeySize() {
        if (tags.containsKey(TAG_KEY_SIZE)) {
            return (Integer) tags.get(TAG_KEY_SIZE);
        }

        return -1;
    }

    public int getKeyAlgorithm() {
        if (tags.containsKey(TAG_ALGORITHM)) {
            return (Integer) tags.get(TAG_ALGORITHM);
        }

        return -1;
    }

    public String getKeyAlgorithmName() {
        if (tags.containsKey(TAG_ALGORITHM)) {
            int alg = (Integer) tags.get(TAG_ALGORITHM);
            switch (alg) {
                case ALGORITHM_RSA:
                    return "RSA";
                case ALGORITHM_EC:
                    return "EC";
                case ALGORITHM_AES:
                    return "AES";
                case ALGORITHM_HMAC:
                    return "HMAC";
                default:
                    throw new IllegalStateException("Uknown algorithm " + alg);
            }
        }

        return null;
    }
}
