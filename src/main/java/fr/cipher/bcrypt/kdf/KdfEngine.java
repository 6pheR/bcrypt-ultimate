package fr.cipher.bcrypt.kdf;

/**
 * A pluggable Key Derivation Function (KDF) interface used to transform passwords
 * into secure cryptographic keys. This can be used to strengthen passwords
 * before feeding them into the bcrypt hashing process.
 *
 * Implementations of this interface may include Argon2, PBKDF2, HKDF, etc.
 */
public interface KdfEngine {

    /**
     * Derives a secure key from a given password and salt.
     *
     * @param password The password as a character array. This array should be securely wiped after use.
     * @param salt     The cryptographically secure salt.
     * @param length   The desired length (in bytes) of the derived key.
     * @return A derived key of the specified length.
     */
    byte[] derive(char[] password, byte[] salt, int length);
}