package fr.cipher.bcrypt.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for Bcrypt-specific Base64 encoding and decoding.
 * <p>
 * Bcrypt uses a custom Base64 alphabet different from standard MIME Base64.
 * This class supports:
 * <ul>
 *     <li>Encoding/decoding using OpenBSD's Bcrypt alphabet</li>
 *     <li>Parsing and reconstructing standard Bcrypt hashes</li>
 *     <li>Extracting cost, salt, and hash parts from a Bcrypt string</li>
 * </ul>
 * <p>
 * Bcrypt Base64 alphabet: "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
 */
public class BcryptEncoding {

    private static final Pattern BCRYPT_PATTERN = Pattern.compile("^\\$(2[abxy])\\$(\\d\\d)\\$(.{22})(.{31})$");
    private static final char[] BCRYPT_BASE64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
    private static final int[] INDEX_64 = new int[128];

	/**
	 * Private constructor to prevent instantiation of this utility class. This
	 * class is meant to provide static constants only.
	 */
    private BcryptEncoding() {}

    static {
        for (int i = 0; i < INDEX_64.length; i++) {
            INDEX_64[i] = -1;
        }
        for (int i = 0; i < BCRYPT_BASE64.length; i++) {
            INDEX_64[BCRYPT_BASE64[i]] = i;
        }
    }

    /**
     * Encodes the given byte array using Bcrypt's custom Base64 format.
     *
     * @param d      Input byte array.
     * @param length Number of bytes to encode.
     * @return Base64-encoded string using Bcrypt alphabet.
     */
    public static String encodeBase64(byte[] d, int length) {
        StringBuilder encoded = new StringBuilder();
        int offset = 0;

        while (offset < length) {
            int c1 = d[offset++] & 0xff;
            encoded.append(BCRYPT_BASE64[(c1 >> 2) & 0x3f]);
            c1 = (c1 & 0x03) << 4;

            if (offset >= length) {
                encoded.append(BCRYPT_BASE64[c1 & 0x3f]);
                break;
            }

            int c2 = d[offset++] & 0xff;
            c1 |= (c2 >> 4) & 0x0f;
            encoded.append(BCRYPT_BASE64[c1 & 0x3f]);
            c1 = (c2 & 0x0f) << 2;

            if (offset >= length) {
                encoded.append(BCRYPT_BASE64[c1 & 0x3f]);
                break;
            }

            int c3 = d[offset++] & 0xff;
            c1 |= (c3 >> 6) & 0x03;
            encoded.append(BCRYPT_BASE64[c1 & 0x3f]);
            encoded.append(BCRYPT_BASE64[c3 & 0x3f]);
        }
        return encoded.toString();
    }

    /**
     * Decodes a Bcrypt Base64-encoded string into a byte array.
     *
     * @param s         Base64-encoded input string.
     * @param maxLength Maximum output length in bytes.
     * @return Decoded byte array.
     */
    public static byte[] decodeBase64(String s, int maxLength) {
        int offset = 0, sLength = s.length(), outputLength = 0;
        byte[] decoded = new byte[maxLength];

        int c1, c2, c3, c4, output;
        while (offset < sLength - 1 && outputLength < maxLength) {
            c1 = char64(s.charAt(offset++));
            c2 = char64(s.charAt(offset++));
            if (c1 == -1 || c2 == -1) break;

            output = (c1 << 2) | ((c2 & 0x30) >> 4);
            decoded[outputLength++] = (byte) (output & 0xff);

            if (outputLength >= maxLength || offset >= sLength) break;

            c3 = char64(s.charAt(offset++));
            if (c3 == -1) break;

            output = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);
            decoded[outputLength++] = (byte) (output & 0xff);

            if (outputLength >= maxLength || offset >= sLength) break;

            c4 = char64(s.charAt(offset++));
            output = ((c3 & 0x03) << 6) | c4;
            decoded[outputLength++] = (byte) (output & 0xff);
        }
        return decoded;
    }

    /**
     * Returns the Base64 index of the given character.
     *
     * @param x Input character.
     * @return Index in Bcrypt Base64 alphabet, or -1 if invalid.
     */
    private static int char64(char x) {
        if (x < 0 || x > 127) return -1;
        return INDEX_64[x];
    }

    /**
     * Extracts the 16-byte salt from a full bcrypt hash string.
     *
     * @param bcryptHash A full bcrypt hash string.
     * @return The decoded salt as bytes.
     */
    public static byte[] extractSalt(String bcryptHash) {
        Matcher m = BCRYPT_PATTERN.matcher(bcryptHash);
        if (!m.matches()) throw new IllegalArgumentException("Invalid bcrypt format");
        return decodeBase64(m.group(3), 16);
    }

    /**
     * Extracts the cost factor from the bcrypt hash string.
     *
     * @param bcryptHash The bcrypt hash string.
     * @return Cost factor as an integer.
     */
    public static int extractCost(String bcryptHash) {
        Matcher m = BCRYPT_PATTERN.matcher(bcryptHash);
        if (!m.matches()) throw new IllegalArgumentException("Invalid bcrypt format");
        return Integer.parseInt(m.group(2));
    }

    /**
     * Extracts the raw hash (23 bytes) from a full bcrypt hash.
     *
     * @param bcryptHash Full bcrypt hash string.
     * @return Decoded raw hash as a byte array.
     */
    public static byte[] extractHash(String bcryptHash) {
        Matcher m = BCRYPT_PATTERN.matcher(bcryptHash);
        if (!m.matches()) throw new IllegalArgumentException("Invalid bcrypt format");
        return decodeBase64(m.group(4), 23);
    }

    /**
     * Builds a bcrypt hash prefix using the salt and cost.
     *
     * @param salt  16-byte salt.
     * @param cost  Cost factor.
     * @return Encoded prefix including version, cost, and salt.
     */
    public static String encodeSalt(byte[] salt, int cost) {
        if (salt.length != 16) throw new IllegalArgumentException("Salt must be 16 bytes");
        return String.format("$2b$%02d$%s", cost, encodeBase64(salt, salt.length));
    }

    /**
     * Builds a complete bcrypt hash string from cost, salt, and raw hash.
     *
     * @param salt  16-byte salt.
     * @param cost  Cost factor.
     * @param hash  23-byte raw bcrypt hash.
     * @return Full bcrypt hash string.
     */
    public static String encodeHash(byte[] salt, int cost, byte[] hash) {
        String saltStr = encodeSalt(salt, cost);
        String hashStr = encodeBase64(hash, 23);
        return saltStr + hashStr;
    }

    /**
     * Checks if a given string is a valid bcrypt hash.
     *
     * @param hash Hash string to validate.
     * @return True if valid bcrypt format, false otherwise.
     */
    public static boolean isValidHash(String hash) {
        return BCRYPT_PATTERN.matcher(hash).matches();
    }
}
