package fr.cipher.bcrypt.core.blowfish;

import java.util.Arrays;

/**
 * Implementation of EksBlowfish – a modified version of the Blowfish cipher
 * tailored for the Bcrypt algorithm.
 */
public final class EksBlowfish {

    // Original constants for the Blowfish cipher as specified
    private static final int[] P_ORIG = new int[] {
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
        0x9216d5d9, 0x8979fb1b
    };

    private static final int[] S_ORIG = BlowfishConstants.S_ORIG;

    // Private constructor to prevent instantiation
    private EksBlowfish() {}

    /**
     * Main Bcrypt function.
     *
     * @param password The password (with a null terminator).
     * @param salt     The salt used for hashing.
     * @param cost     The cost factor (log2 of the number of iterations).
     * @return A byte array representing the hash.
     */
    public static byte[] bcrypt(byte[] password, byte[] salt, int cost) {
        Blowfish bf = new Blowfish(Arrays.copyOf(P_ORIG, P_ORIG.length), Arrays.copyOf(S_ORIG, S_ORIG.length));

        int rounds = 1 << cost;
        bf.eksKeySchedule(password, salt, rounds);

        byte[] ctext = "OrpheanBeholderScryDoubt".getBytes();
        for (int i = 0; i < 64; i++) {
            ctext = bf.encryptECB(ctext);
        }

        return Arrays.copyOf(ctext, 23);
    }
}