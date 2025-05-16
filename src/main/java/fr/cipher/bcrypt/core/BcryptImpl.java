package fr.cipher.bcrypt.core;

import fr.cipher.bcrypt.core.blowfish.EksBlowfish;
import fr.cipher.bcrypt.util.BcryptEncoding;
import fr.cipher.bcrypt.util.ConstantTimeComparator;
import java.util.Arrays;

/**
 * Internal implementation details for bcrypt hashing and verification.
 *
 * Provides low-level routines including:
 * - hash generation with salt
 * - salt extraction
 * - constant-time comparison
 */
final class BcryptImpl {


	/**
	 * Private constructor to prevent instantiation of this utility class. This
	 * class is meant to provide static constants only.
	 */
    private BcryptImpl() {}

    /**
     * Hashes the input using bcrypt, cost factor, salt, and version.
     *
     * @param input     The raw or derived password bytes.
     * @param cost      The bcrypt cost factor (log rounds).
     * @param saltBytes The 16-byte salt.
     * @param version   The Bcrypt version identifier (e.g., "2b", "2a", "2y").
     * @return A bcrypt hash string.
     */
    static String hash(byte[] input, int cost, byte[] saltBytes, String version) {
        if (saltBytes == null || saltBytes.length != 16) {
            throw new IllegalArgumentException("Salt must be 16 bytes");
        }
        if (!version.matches("2[aby]")) {
            throw new IllegalArgumentException("Invalid bcrypt version: " + version);
        }

        byte[] hash = EksBlowfish.bcrypt(input, saltBytes, cost);
        return BcryptEncoding.encodeHash(saltBytes, cost, hash, version);
    }

    /**
     * Verifies an input against the bcrypt hash.
     *
     * @param input      Raw or KDF'd input.
     * @param hashed     Stored bcrypt hash.
     * @return true if match, false otherwise.
     */
    static boolean check(byte[] input, String hashed) {
        int cost = BcryptEncoding.extractCost(hashed);
        byte[] salt = BcryptEncoding.extractSalt(hashed);
        byte[] expectedHash = BcryptEncoding.extractHash(hashed);

        byte[] recomputed = EksBlowfish.bcrypt(input, salt, cost);
        byte[] recomputedTrunc = Arrays.copyOf(recomputed, expectedHash.length);
        return ConstantTimeComparator.equals(expectedHash, recomputedTrunc);
    }

    /**
     * Extracts the 16-byte salt from a bcrypt hash.
     *
     * @param hash The bcrypt hash.
     * @return The raw salt bytes.
     */
    static byte[] extractSalt(String hash) {
        return BcryptEncoding.extractSalt(hash);
    }
}
