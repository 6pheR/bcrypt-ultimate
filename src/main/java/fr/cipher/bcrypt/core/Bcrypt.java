package fr.cipher.bcrypt.core;

import java.security.SecureRandom;
import java.util.Objects;
import javax.annotation.concurrent.ThreadSafe;

/**
 * High-level Fluent API for Bcrypt hashing and verification.
 * This API provides an easy-to-use interface for hashing passwords
 * and verifying password hashes using the Bcrypt algorithm.
 */
@ThreadSafe
public final class Bcrypt {

    private final BcryptConfig config;
    private final SecureRandom secureRandom;

    private Bcrypt(SecureRandom random, BcryptConfig config) {
        this.secureRandom = Objects.requireNonNull(random, "SecureRandom must not be null");
        this.config = Objects.requireNonNull(config, "BcryptConfig must not be null");
    }

    public static Bcrypt withDefaults() {
        return new Bcrypt(new SecureRandom(), BcryptConfig.builder().setCostFactor(10).build());
    }

    public static Bcrypt create() {
        return withDefaults();
    }

    public static Bcrypt withCost(int cost) {
        return new Bcrypt(new SecureRandom(), BcryptConfig.builder().setCostFactor(cost).build());
    }

    public static Bcrypt withCustom(SecureRandom random, BcryptConfig config) {
        return new Bcrypt(random, config);
    }

    public String hash(String password) {
        return BcryptEngine.hash(password, config, secureRandom);
    }

    public boolean verify(String password, String hash) {
        return BcryptEngine.verify(password, hash, config);
    }

    public Bcrypt withNewConfig(BcryptConfig config) {
        return new Bcrypt(this.secureRandom, config);
    }

    public Bcrypt withSecureRandom(SecureRandom random) {
        return new Bcrypt(random, this.config);
    }

    public BcryptConfig getConfig() {
        return config;
    }
}