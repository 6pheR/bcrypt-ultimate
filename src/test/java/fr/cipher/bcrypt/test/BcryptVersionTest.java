package fr.cipher.bcrypt.test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.SecureRandom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import fr.cipher.bcrypt.core.BcryptConfig;
import fr.cipher.bcrypt.core.BcryptEngine;

/**
 * Advanced tests for Bcrypt versions.
 */
public class BcryptVersionTest {

    @Test
    @DisplayName("Reject invalid version")
    void testEngineRejectsInvalidInputs() {
        String password = "PasswordTest";

		BcryptConfig config = BcryptConfig.builder().setCostFactor(10).setVersion("2x").build();
        SecureRandom random = new SecureRandom();
        
        assertThrows(IllegalArgumentException.class, () -> BcryptEngine.hash(password, config, random));
    }

    @Test
    @DisplayName("Hash and verify with supported bcrypt versions via config")
    void testEngineHashAndVerifyAllVersions() {
        String[] versions = {"2a", "2b", "2y"};
        SecureRandom random = new SecureRandom();
        String password = "secureVersionTest";

        for (String version : versions) {
            BcryptConfig config = BcryptConfig.builder()
                    .setCostFactor(10)
                    .setVersion(version)
                    .build();

            String hash = BcryptEngine.hash(password, config, random);
            assertTrue(hash.startsWith("$" + version + "$"), "Expected prefix $" + version + "$");
            assertTrue(BcryptEngine.verify(password, hash, config), "Should verify for version " + version);
        }
    }	
}
