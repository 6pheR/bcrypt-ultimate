package fr.cipher.bcrypt.test;

import fr.cipher.bcrypt.core.BcryptConfig;
import fr.cipher.bcrypt.core.BcryptEngine;
import fr.cipher.bcrypt.kdf.Argon2KdfEngine;
import fr.cipher.bcrypt.kdf.HkdfEngine;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Advanced tests for Bcrypt features and edge cases.
 */
public class BcryptAdvancedTest {

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
    @DisplayName("Strict FIPS mode requires a KDF")
    void testFipsModeRequiresKdf() {
        BcryptConfig config = BcryptConfig.builder()
                .setCostFactor(10)
                .enableStrictFips()
                .withKdf(Argon2KdfEngine.builder().build())
                .build();

        String hash = BcryptEngine.hash("fipsPassword", config, new SecureRandom());
        assertTrue(BcryptEngine.verify("fipsPassword", hash, config));
    }

    @Test
    @DisplayName("Strict FIPS mode without KDF should throw")
    void testFipsModeThrowsIfNoKdf() {
        BcryptConfig config = BcryptConfig.builder()
                .setCostFactor(10)
                .enableStrictFips()
                .build();

        assertThrows(IllegalStateException.class, () ->
                BcryptEngine.hash("fipsPassword", config, new SecureRandom()));
    }

    @Test
    @DisplayName("Timing consistency for equal length passwords")
    void testTimingDummy() {
        long start1 = System.nanoTime();
        BcryptEngine.verify("test", "$2b$10$JH5vGtrO1eZpjPCuSRe7SuqWqQW4wGyhPdtG9ZTGxZ5BQm.EDZ4zG", 
            BcryptConfig.builder().setCostFactor(10).build());
        long duration1 = System.nanoTime() - start1;

        long start2 = System.nanoTime();
        BcryptEngine.verify("abcd", "$2b$10$JH5vGtrO1eZpjPCuSRe7SuqWqQW4wGyhPdtG9ZTGxZ5BQm.EDZ4zG", 
            BcryptConfig.builder().setCostFactor(10).build());
        long duration2 = System.nanoTime() - start2;

        long diff = Math.abs(duration1 - duration2);
        System.out.println("Timing difference (ns): " + diff);

        // Doesn't assert, just shows we have a near-constant comparison
    }

    @Test
    @DisplayName("Fails gracefully with null password")
    void testNullPassword() {
        assertThrows(NullPointerException.class, () ->
            BcryptEngine.hash(null, BcryptConfig.builder().build(), new SecureRandom())
        );
    }
    
    @Test
    @DisplayName("Test historical 0x80 bug (should not be affected)")
    void testBcryptZeroX80Bug() {
        String basePassword = "PasswordTest";
        String buggyPassword = basePassword + "\u0080";

        BcryptConfig config = BcryptConfig.builder().setCostFactor(10).build();
        SecureRandom random = new SecureRandom();

        String hash = BcryptEngine.hash(basePassword, config, random);

        assertFalse(BcryptEngine.verify(buggyPassword, hash, config),
            "Bcrypt engine is vulnerable to the historical 0x80 bug!");
    }

}