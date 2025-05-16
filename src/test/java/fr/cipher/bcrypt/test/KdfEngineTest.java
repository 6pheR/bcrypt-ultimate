package fr.cipher.bcrypt.test;

import fr.cipher.bcrypt.core.BcryptConfig;
import fr.cipher.bcrypt.core.BcryptEngine;
import fr.cipher.bcrypt.kdf.Argon2KdfEngine;
import fr.cipher.bcrypt.kdf.HkdfEngine;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.security.SecureRandom;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for all Key Derivation Function (KDF) engines:
 * - Argon2KdfEngine
 * - HkdfEngine
 */
class KdfEngineTest {

    private static final char[] PASSWORD = "securePassword!".toCharArray();
    private static final int HASH_LENGTH = 32;

    // -------------------- ARGON2 TESTS --------------------
    
    @Test
    @DisplayName("Hashing with Argon2 KDF engine")
    void testHashWithArgon2() {
        var kdf = Argon2KdfEngine.builder()
                .timeCost(2)
                .memoryCost(65536)
                .parallelism(2)
                .hashLength(32)
                .build();

        BcryptConfig config = BcryptConfig.builder()
                .setCostFactor(10)
                .withKdf(kdf)
                .build();

        String hash = BcryptEngine.hash("secureKDF", config, new SecureRandom());
        assertTrue(BcryptEngine.verify("secureKDF", hash, config));
    }
    
    @Test
    void testDerive_returnsConsistentLength() {
        Argon2KdfEngine engine = Argon2KdfEngine.builder()
            .timeCost(2)
            .memoryCost(32768)
            .parallelism(1)
            .hashLength(HASH_LENGTH)
            .build();

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] derived = engine.derive(PASSWORD, salt, HASH_LENGTH);
        assertNotNull(derived);
        assertEquals(HASH_LENGTH, derived.length);
    }

    @Test
    void testDerive_returnsDifferentOutputsForDifferentSalts() {
        Argon2KdfEngine engine = Argon2KdfEngine.builder().build();

        byte[] salt1 = new byte[16];
        byte[] salt2 = new byte[16];
        new SecureRandom().nextBytes(salt1);
        new SecureRandom().nextBytes(salt2);

        byte[] derived1 = engine.derive(PASSWORD, salt1, HASH_LENGTH);
        byte[] derived2 = engine.derive(PASSWORD, salt2, HASH_LENGTH);

        assertFalse(Arrays.equals(derived1, derived2), "Derived keys should differ for different salts");
    }

    @Test
    void testDerive_returnsSameOutputForSameInput() {
        Argon2KdfEngine engine = Argon2KdfEngine.builder().build();

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] derived1 = engine.derive(PASSWORD, salt, HASH_LENGTH);
        byte[] derived2 = engine.derive(PASSWORD, salt, HASH_LENGTH);

        assertArrayEquals(derived1, derived2, "Derived keys should be equal for same input");
    }

    @Test
    void testDerive_throwsExceptionForShortSalt() {
        Argon2KdfEngine engine = Argon2KdfEngine.builder().build();

        byte[] shortSalt = new byte[4];

        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> engine.derive(PASSWORD, shortSalt, HASH_LENGTH)
        );

        assertTrue(ex.getMessage().contains("Salt must not be null and must be at least 8 bytes long"));
    }

    @Test
    void testDerive_throwsExceptionForLengthMismatch() {
        Argon2KdfEngine engine = Argon2KdfEngine.builder().hashLength(HASH_LENGTH).build();

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> engine.derive(PASSWORD, salt, 64)
        );

        assertTrue(ex.getMessage().contains("Mismatch"));
    }
    
    // -------------------- HKDF TESTS --------------------

    @Test
    @DisplayName("Hashing with HKDF engine")
    void testHashWithHkdf() {
        var kdf = new HkdfEngine();

        BcryptConfig config = BcryptConfig.builder()
                .setCostFactor(10)
                .withKdf(kdf)
                .build();

        String hash = BcryptEngine.hash("secureHKDF", config, new SecureRandom());
        assertTrue(BcryptEngine.verify("secureHKDF", hash, config));
    }
    
    @Test
    void testHkdf_returnsCorrectLength() {
        HkdfEngine engine = new HkdfEngine();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] derived = engine.derive(PASSWORD, salt, HASH_LENGTH);
        assertNotNull(derived);
        assertEquals(HASH_LENGTH, derived.length);
    }

    @Test
    void testHkdf_returnsDifferentOutputsForDifferentSalts() {
        HkdfEngine engine = new HkdfEngine();
        byte[] salt1 = new byte[16];
        byte[] salt2 = new byte[16];
        new SecureRandom().nextBytes(salt1);
        new SecureRandom().nextBytes(salt2);

        byte[] derived1 = engine.derive(PASSWORD, salt1, HASH_LENGTH);
        byte[] derived2 = engine.derive(PASSWORD, salt2, HASH_LENGTH);

        assertFalse(Arrays.equals(derived1, derived2), "HKDF: Keys should differ for different salts");
    }

    @Test
    void testHkdf_returnsSameOutputForSameInput() {
        HkdfEngine engine = new HkdfEngine();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] derived1 = engine.derive(PASSWORD, salt, HASH_LENGTH);
        byte[] derived2 = engine.derive(PASSWORD, salt, HASH_LENGTH);

        assertArrayEquals(derived1, derived2, "HKDF: Keys should match for same input");
    }

    @Test
    void testHkdf_throwsExceptionForShortSalt() {
        HkdfEngine engine = new HkdfEngine();
        byte[] shortSalt = new byte[4];

        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> engine.derive(PASSWORD, shortSalt, HASH_LENGTH)
        );

        assertTrue(ex.getMessage().contains("Salt must not be null and must be at least 8 bytes long"));
    }

    @Test
    void testHkdf_throwsExceptionForZeroLength() {
        HkdfEngine engine = new HkdfEngine();
        byte[] salt = new byte[16];

        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> engine.derive(PASSWORD, salt, 0)
        );

        assertTrue(ex.getMessage().contains("Length must be greater than 0"));
    }
}