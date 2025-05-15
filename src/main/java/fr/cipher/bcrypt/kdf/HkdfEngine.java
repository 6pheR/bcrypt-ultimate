package fr.cipher.bcrypt.kdf;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * An implementation of the HMAC-based Key Derivation Function (HKDF).
 * <p>
 * HKDF is specified in <a href="https://tools.ietf.org/html/rfc5869">RFC 5869</a>.
 * It uses HMAC (e.g., HmacSHA256) to securely derive strong cryptographic keys from weak input material.
 * <p>
 * This engine supports usage within a secure password hashing flow, such as pre-processing for bcrypt.
 * 
 * Default configuration uses HmacSHA256.
 */
public final class HkdfEngine implements KdfEngine {

    /** Default HMAC algorithm (RFC 5869 recommends SHA-256). */
    private static final String DEFAULT_ALGORITHM = "HmacSHA256";

    /** The chosen HMAC algorithm to use for derivation (e.g., HmacSHA256, HmacSHA512). */
    private final String algorithm;

    /**
     * Constructs a new HKDF engine with default algorithm (HmacSHA256).
     */
    public HkdfEngine() {
        this(DEFAULT_ALGORITHM);
    }

    /**
     * Constructs a new HKDF engine with a custom HMAC algorithm.
     *
     * @param algorithm The HMAC algorithm to use (e.g., "HmacSHA512").
     */
    public HkdfEngine(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Derives a secure key using HKDF with the specified password and salt.
     *
     * @param password The input password as a character array (typically user-provided).
     * @param salt     A cryptographically secure random salt (minimum 8 bytes recommended).
     * @param length   Desired output key length in bytes.
     * @return A derived key of the specified length.
     * @throws IllegalArgumentException if salt is null or too short.
     * @throws RuntimeException if HKDF fails during internal operations.
     */
    @Override
    public byte[] derive(char[] password, byte[] salt, int length) {
        if (salt == null || salt.length < 8) {
            throw new IllegalArgumentException("Salt must not be null and must be at least 8 bytes long");
        }
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be greater than 0");
        }

        try {
            byte[] inputKey = new String(password).getBytes(StandardCharsets.UTF_8);
            byte[] prk = extract(salt, inputKey);
            return expand(prk, length);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("HKDF key derivation failed", e);
        }
    }

    /**
     * Performs the HKDF-Extract step.
     * Computes a pseudorandom key (PRK) from the input key material and salt using HMAC.
     *
     * @param salt     The salt value.
     * @param inputKey The input keying material (IKM), e.g., password bytes.
     * @return A pseudorandom key (PRK).
     * @throws GeneralSecurityException If the algorithm is invalid or HMAC fails.
     */
    private byte[] extract(byte[] salt, byte[] inputKey) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(salt, algorithm);
        mac.init(keySpec);
        return mac.doFinal(inputKey);
    }

    /**
     * Performs the HKDF-Expand step.
     * Expands the pseudorandom key (PRK) into the final derived key.
     *
     * @param prk    The pseudorandom key from the extract step.
     * @param length The desired output key length in bytes.
     * @return A derived key of the requested length.
     * @throws GeneralSecurityException If HMAC fails.
     */
    private byte[] expand(byte[] prk, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(prk, algorithm));

        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int bytesWritten = 0;
        int counter = 1;

        while (bytesWritten < length) {
            mac.update(t);
            mac.update((byte) counter);
            t = mac.doFinal();

            int copyLength = Math.min(t.length, length - bytesWritten);
            System.arraycopy(t, 0, result, bytesWritten, copyLength);
            bytesWritten += copyLength;
            counter++;
        }
        return result;
    }
}