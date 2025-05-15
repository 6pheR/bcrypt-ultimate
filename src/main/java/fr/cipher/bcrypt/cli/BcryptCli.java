package fr.cipher.bcrypt.cli;

import fr.cipher.bcrypt.core.BcryptConfig;
import fr.cipher.bcrypt.core.BcryptEngine;
import fr.cipher.bcrypt.kdf.Argon2KdfEngine;
import org.apache.commons.cli.*;

import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Command-Line Interface (CLI) for bcrypt password hashing and verification.
 *
 * Supports advanced options like cost factor tuning, strict FIPS mode,
 * and optional Argon2-based key derivation.
 */
public class BcryptCli {

    public static void main(String[] args) {
        Options options = new Options();

        options.addOption("h", "hash", false, "Hash a password");
        options.addOption("v", "verify", false, "Verify a password");
        options.addOption("p", "password", true, "Password to hash or verify");
        options.addOption("c", "cost", true, "Cost factor (default: 12)");
        options.addOption("s", "strict", false, "Enable strict FIPS mode");
        options.addOption("k", "kdf", false, "Use Argon2 key derivation");
        options.addOption("H", "hashvalue", true, "Hashed value to verify against");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        int exitCode = 1;

        try {
            CommandLine cmd = parser.parse(options, args);

            if (!cmd.hasOption("hash") && !cmd.hasOption("verify")) {
                formatter.printHelp("bcrypt-cli", options);
                System.exit(exitCode);
            }

            String password = cmd.getOptionValue("password");
            if (password == null || password.isEmpty()) {
                System.out.print("Enter password: ");
                try (Scanner scanner = new Scanner(System.in)) {
                    password = scanner.nextLine();
                }
            }

            int cost = Integer.parseInt(cmd.getOptionValue("cost", "12"));
            boolean strictFips = cmd.hasOption("strict");
            boolean useKdf = cmd.hasOption("kdf");

            BcryptConfig.Builder builder = BcryptConfig.builder().setCostFactor(cost);
            if (strictFips) builder.enableStrictFips();
            if (useKdf) {
                builder.withKdf(Argon2KdfEngine.builder()
                        .timeCost(3)
                        .memoryCost(65536)
                        .parallelism(2)
                        .hashLength(32)
                        .build());
            }

            BcryptConfig config = builder.build();

            if (cmd.hasOption("hash")) {
                String hash = BcryptEngine.hash(password, config, new SecureRandom());
                System.out.println("Hash: " + hash);
                exitCode = 0;
            } else if (cmd.hasOption("verify")) {
                String hashToVerify = cmd.getOptionValue("hashvalue");
                if (hashToVerify == null || hashToVerify.isEmpty()) {
                    System.err.println("Error: Missing --hashvalue for verification.");
                } else {
                    boolean match = BcryptEngine.verify(password, hashToVerify, config);
                    System.out.println("Match: " + match);
                    exitCode = match ? 0 : 1;
                }
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            formatter.printHelp("bcrypt-cli", options);
        }

        System.exit(exitCode);
    }
}