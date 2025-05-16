package fr.cipher.bcrypt.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for Bcrypt-specific Base64 encoding and decoding.
 *
 * Bcrypt uses a custom Base64 alphabet distinct from standard Base64:
 * <pre>
 * "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
 * </pre>
 * This class handles:
 * <ul>
 *   <li>Encoding/decoding in Bcrypt-compatible Base64</li>
 *   <li>Parsing and extracting salt/cost/hash/version from Bcrypt hash strings</li>
 *   <li>Constructing full Bcrypt hashes from components</li>
 * </ul>
 */
public class BcryptEncoding {

    private static final Pattern BCRYPT_PATTERN = Pattern.compile("^\\$(2[aby])\\$(\\d\\d)\\$(.{22})(.{31})$");
    private static final char[] BCRYPT_BASE64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
    private static final int[] INDEX_64 = new int[128];

    /**
     * Prevent instantiation.
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
     * Encodes bytes using Bcrypt-compatible Base64.
     *
     * @param d      byte array to encode
     * @param length number of bytes to encode
     * @return Base64-encoded string
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
     * Decodes Bcrypt Base64-encoded string.
     *
     * @param s         Base64 string
     * @param maxLength maximum output length
     * @return decoded byte array
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
     * Maps Base64 character to integer index.
     */
    private static int char64(char x) {
        if (x < 0 || x > 127) return -1;
        return INDEX_64[x];
    }

    /**
     * Extracts the salt portion from a Bcrypt hash.
     *
     * @param bcryptHash full bcrypt hash
     * @return 16-byte decoded salt
     */
    public static byte[] extractSalt(String bcryptHash) {
        Matcher m = BCRYPT_PATTERN.matcher(bcryptHash);
        if (!m.matches()) throw new IllegalArgumentException("Invalid bcrypt format");
        return decodeBase64(m.group(3), 16);
    }

    /**
     * Extracts the cost factor (as integer) from a Bcrypt hash.
     */
    public static int extractCost(String bcryptHash) {
        Matcher m = BCRYPT_PATTERN.matcher(bcryptHash);
        if (!m.matches()) throw new IllegalArgumentException("Invalid bcrypt format");
        return Integer.parseInt(m.group(2));
    }

    /**
     * Extracts the 23-byte raw hash from a full Bcrypt string.
     */
    public static byte[] extractHash(String bcryptHash) {
        Matcher m = BCRYPT_PATTERN.matcher(bcryptHash);
        if (!m.matches()) throw new IllegalArgumentException("Invalid bcrypt format");
        return decodeBase64(m.group(4), 23);
    }

    /**
     * Extracts the version prefix (e.g., "2b", "2y", "2a") from the Bcrypt hash.
     */
    public static String extractVersion(String bcryptHash) {
        Matcher m = BCRYPT_PATTERN.matcher(bcryptHash);
        if (!m.matches()) throw new IllegalArgumentException("Invalid bcrypt format");
        return m.group(1);
    }
    
    /**
     * Builds a Bcrypt salt prefix with custom version.
     *
     * @param salt    16-byte salt
     * @param cost    cost factor
     * @param version bcrypt version string (e.g., "2b")
     */
    public static String encodeSalt(byte[] salt, int cost, String version) {
        if (salt.length != 16) throw new IllegalArgumentException("Salt must be 16 bytes");
        if (!version.matches("2[aby]")) throw new IllegalArgumentException("Unsupported Bcrypt version");
        return String.format("$%s$%02d$%s", version, cost, encodeBase64(salt, salt.length));
    }

    /**
     * Builds a complete Bcrypt hash string with version control.
     *
     * @param salt    16-byte salt
     * @param cost    cost factor
     * @param hash    23-byte raw hash
     * @param version bcrypt version ("2b", "2a", "2y")
     */
    public static String encodeHash(byte[] salt, int cost, byte[] hash, String version) {
        String saltStr = encodeSalt(salt, cost, version);
        String hashStr = encodeBase64(hash, 23);
        return saltStr + hashStr;
    }

    /**
     * Validates whether the given string matches Bcrypt hash format.
     */
    public static boolean isValidHash(String hash) {
        return BCRYPT_PATTERN.matcher(hash).matches();
    }
}
