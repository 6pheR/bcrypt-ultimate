package fr.cipher.bcrypt.core;

import fr.cipher.bcrypt.kdf.KdfEngine;

/**
 * Immutable configuration for the Bcrypt hashing engine.
 * <p>
 * This config object can include options like cost factor, strict FIPS mode,
 * hash version (e.g., $2b$, $2y$), and an optional KDF engine.
 */
public final class BcryptConfig {

    private final int costFactor;
    private final boolean strictFips;
    private final KdfEngine kdfEngine;
    private final String version;

    private BcryptConfig(Builder builder) {
        this.costFactor = builder.costFactor;
        this.strictFips = builder.strictFips;
        this.kdfEngine = builder.kdfEngine;
        this.version = builder.version;
    }

    public int getCostFactor() {
        return costFactor;
    }

    public boolean isStrictFips() {
        return strictFips;
    }

    public KdfEngine getKdfEngine() {
        return kdfEngine;
    }

    public String getVersion() {
        return version;
    }

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
        private String version = "2b";

        public Builder setCostFactor(int costFactor) {
            this.costFactor = costFactor;
            return this;
        }

        public Builder enableStrictFips() {
            this.strictFips = true;
            return this;
        }

        public Builder withKdf(KdfEngine kdfEngine) {
            this.kdfEngine = kdfEngine;
            return this;
        }

        /**
         * Sets the version prefix of the Bcrypt hash ($2a$, $2b$, $2y$).
         *
         * @param version version string, e.g., "2b"
         * @return this builder
         */
        public Builder setVersion(String version) {
            this.version = version;
            return this;
        }

        public BcryptConfig build() {
            return new BcryptConfig(this);
        }
    }
}