package fr.cipher.bcrypt.test;

import fr.cipher.bcrypt.core.BcryptConfig;
import fr.cipher.bcrypt.core.BcryptEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.security.SecureRandom;

/**
 * Unit tests for basic Bcrypt hashing and verification.
 */
public class BcryptTest {

    @Test
    @DisplayName("Hash and verify password correctly")
    void testHashAndVerify() {
        BcryptConfig config = BcryptConfig.builder().setCostFactor(10).build();
        String hash = BcryptEngine.hash("password123", config, new SecureRandom());
        assertTrue(BcryptEngine.verify("password123", hash, config));
    }

    @Test
    @DisplayName("Verification fails for incorrect password")
    void testInvalidPassword() {
        BcryptConfig config = BcryptConfig.builder().build();
        String hash = BcryptEngine.hash("hello", config, new SecureRandom());
        assertFalse(BcryptEngine.verify("wrong", hash, config));
    }
}