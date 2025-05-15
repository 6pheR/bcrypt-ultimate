package fr.cipher.bcrypt.test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for the Bcrypt CLI.
 */
public class BcryptCliTest {

    @Test
    @DisplayName("CLI: Hash password using --hash")
    void testCliHashCommand() throws Exception {
        ProcessBuilder pb = new ProcessBuilder("java", "-jar", "target/bcrypt-ultimate-1.0.0-jar-with-dependencies.jar", 
            "--hash", "--password", "cliTest123", "--cost", "10");

        pb.redirectErrorStream(true);
        Process process = pb.start();

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        String hash = null;

        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
            if (line.startsWith("Hash: ")) {
                hash = line.substring(6).trim();
            }
        }

        int exitCode = process.waitFor();
        assertEquals(0, exitCode, "CLI exited with non-zero status");
        assertNotNull(hash, "Hash not produced by CLI");
        assertTrue(hash.startsWith("$2b$10$"));
    }
}