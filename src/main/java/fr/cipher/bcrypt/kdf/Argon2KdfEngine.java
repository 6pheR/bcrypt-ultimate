package fr.cipher.bcrypt.kdf;

import com.kosprov.jargon2.api.Jargon2;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * A configurable Argon2 Key Derivation Function engine.
 * Uses native bindings (jargon2) for secure password hashing.
 *
 * Fully immutable, thread-safe and fluent.
 */
public final class Argon2KdfEngine implements KdfEngine {

    private final int timeCost;
    private final int memoryCost;
    private final int parallelism;
    private final int hashLength;
    private final Jargon2.Type type;

    private Argon2KdfEngine(Builder builder) {
        this.timeCost = builder.timeCost;
        this.memoryCost = builder.memoryCost;
        this.parallelism = builder.parallelism;
        this.hashLength = builder.hashLength;
        this.type = builder.type;
    }

    /**
     * Derives a cryptographic key from the given password and salt using Argon2.
     *
     * @param password  The password as a char array (never null).
     * @param salt      The salt as a byte array (never null).
     * @param length    Length of the derived key (bytes). Must match configured length.
     * @return The derived key as byte array.
     */
    @Override
    public byte[] derive(char[] password, byte[] salt, int length) {
        Objects.requireNonNull(password, "Password must not be null");
        Objects.requireNonNull(salt, "Salt must not be null");
        
        if (salt == null || salt.length < 8) {
            throw new IllegalArgumentException("Salt must not be null and must be at least 8 bytes long");
        }
        if (length != hashLength) {
            throw new IllegalArgumentException("Mismatch: configured hash length != requested length");
        }

        byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);

        Jargon2.Hasher hasher = Jargon2.jargon2Hasher()
                .type(type)
                .memoryCost(memoryCost)
                .timeCost(timeCost)
                .parallelism(parallelism)
                .salt(salt)
                .hashLength(hashLength)
                .password(passwordBytes);

        byte[] result = hasher.rawHash();
        Arrays.fill(passwordBytes, (byte) 0);

        return result;
    }

    /**
     * Begins fluent configuration of a new Argon2 KDF engine.
     * @return a builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for Argon2KdfEngine with secure defaults.
     */
    public static final class Builder {
        private int timeCost = 3;
        private int memoryCost = 65536;
        private int parallelism = 2;
        private int hashLength = 32;
        private Jargon2.Type type = Jargon2.Type.ARGON2id;

        public Builder timeCost(int timeCost) {
            this.timeCost = timeCost;
            return this;
        }

        public Builder memoryCost(int memoryCost) {
            this.memoryCost = memoryCost;
            return this;
        }

        public Builder parallelism(int parallelism) {
            this.parallelism = parallelism;
            return this;
        }

        public Builder hashLength(int hashLength) {
            this.hashLength = hashLength;
            return this;
        }

        public Builder type(Jargon2.Type type) {
            this.type = type;
            return this;
        }

        public Argon2KdfEngine build() {
            return new Argon2KdfEngine(this);
        }
    }
}
