package fr.cipher.bcrypt.core;

import fr.cipher.bcrypt.kdf.KdfEngine;

/**
 * Immutable configuration for the Bcrypt hashing engine.
 * 
 * This config object can include options like cost factor, strict FIPS mode, and an optional KDF engine.
 * It uses a fluent builder for safe, null-free configuration.
 */
public final class BcryptConfig {

    private final int costFactor;
    private final boolean strictFips;
    private final KdfEngine kdfEngine;

    private BcryptConfig(Builder builder) {
        this.costFactor = builder.costFactor;
        this.strictFips = builder.strictFips;
        this.kdfEngine = builder.kdfEngine;
    }

    /**
     * Returns the computational cost factor (2^cost).
     *
     * @return the cost factor
     */
    public int getCostFactor() {
        return costFactor;
    }

    /**
     * Indicates whether strict FIPS compatibility is enabled.
     *
     * @return true if FIPS mode is enabled, false otherwise
     */
    public boolean isStrictFips() {
        return strictFips;
    }

    /**
     * Returns the configured KDF engine, if any.
     *
     * @return an optional KDF engine, or null if none
     */
    public KdfEngine getKdfEngine() {
        return kdfEngine;
    }

    /**
     * Begins building a new BcryptConfig.
     *
     * @return a fluent builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for BcryptConfig.
     * Ensures all fields are valid before instantiation.
     */
    public static final class Builder {
        private int costFactor = 12;
        private boolean strictFips = false;
        private KdfEngine kdfEngine;

        /**
         * Sets the cost factor (log rounds).
         *
         * @param costFactor e.g., 12 for 2^12 iterations
         * @return this builder
         */
        public Builder setCostFactor(int costFactor) {
            this.costFactor = costFactor;
            return this;
        }

        /**
         * Enables strict FIPS mode (may disable Blowfish).
         *
         * @return this builder
         */
        public Builder enableStrictFips() {
            this.strictFips = true;
            return this;
        }

        /**
         * Adds a KDF engine to pre-process the password.
         *
         * @param kdfEngine the key derivation function engine
         * @return this builder
         */
        public Builder withKdf(KdfEngine kdfEngine) {
            this.kdfEngine = kdfEngine;
            return this;
        }

        /**
         * Builds the final immutable config object.
         *
         * @return a new BcryptConfig
         */
        public BcryptConfig build() {
            return new BcryptConfig(this);
        }
    }
}