package fr.cipher.bcrypt.core;

import fr.cipher.bcrypt.kdf.KdfEngine;

import java.security.SecureRandom;

/**
 * The core engine responsible for bcrypt password hashing and verification.
 *
 * This class handles the full lifecycle of generating and verifying bcrypt hashes.
 * Supports optional pre-processing via a KDF engine (e.g., Argon2).
 *
 * FIPS mode note:
 * When strictFips is enabled, this engine enforces the use of a KDF and blocks
 * direct usage of EksBlowfish (non-FIPS-compliant).
 */
public final class BcryptEngine {

	/**
	 * Private constructor to prevent instantiation of this utility class. This
	 * class is meant to provide static constants only.
	 */
    private BcryptEngine() {}

    /**
     * Hashes the given password using the provided configuration and secure random instance.
     * If strictFips is enabled, a FIPS-approved KDF must be present.
     *
     * @param password The raw password to hash.
     * @param config   The hashing configuration including cost, KDF, etc.
     * @param random   A secure random number generator for salt generation.
     * @return A bcrypt hash string.
     */
    public static String hash(String password, BcryptConfig config, SecureRandom random) {
        if (config.isStrictFips()) {
            if (config.getKdfEngine() == null) {
                throw new IllegalStateException("Strict FIPS mode requires a FIPS-compliant KDF (e.g., Argon2).");
            }
        }

        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] passwordBytes = password.getBytes();

        KdfEngine kdf = config.getKdfEngine();
        byte[] input = (kdf != null)
                ? kdf.derive(password.toCharArray(), salt, 32)
                : passwordBytes;

        return BcryptImpl.hash(input, config.getCostFactor(), salt);
    }

    /**
     * Verifies a raw password against a previously hashed bcrypt string.
     * If strictFips is enabled, direct verification of Blowfish hashes without a KDF is blocked.
     *
     * @param password  The input password to check.
     * @param hashed    The bcrypt hash string to compare against.
     * @param config    The hashing config to use (including optional KDF).
     * @return true if the password matches the hash, false otherwise.
     */
    public static boolean verify(String password, String hashed, BcryptConfig config) {
        if (config.isStrictFips()) {
            if (config.getKdfEngine() == null) {
                throw new IllegalStateException("Strict FIPS mode cannot verify raw Blowfish hashes without a KDF.");
            }
        }

        byte[] salt = BcryptImpl.extractSalt(hashed);
        byte[] passwordBytes = password.getBytes();

        KdfEngine kdf = config.getKdfEngine();
        byte[] input = (kdf != null)
                ? kdf.derive(password.toCharArray(), salt, 32)
                : passwordBytes;

        return BcryptImpl.check(input, hashed);
    }
}
