package fr.cipher.bcrypt.core.blowfish;

import java.util.Arrays;

/**
 * Internal implementation of the Blowfish cipher.
 * Provides support for ECB (Electronic Code Book) mode encryption
 * and the EksBlowfish Key Schedule used in Bcrypt.
 */
public class Blowfish {

    private int[] P; // P-array for the Blowfish cipher.
    private int[] S; // S-boxes for the Blowfish cipher.

    /**
     * Constructs a Blowfish instance with the given P-array and S-boxes.
     *
     * @param p The initial P-array.
     * @param s The initial S-boxes.
     */
    public Blowfish(int[] p, int[] s) {
        this.P = Arrays.copyOf(p, p.length);
        this.S = Arrays.copyOf(s, s.length);
    }

    /**
     * Executes the EksBlowfish Key Schedule, which is computationally expensive.
     * This involves initializing the P-array and S-boxes with the provided key,
     * salt, and the specified number of rounds.
     *
     * @param key    The key used to initialize the cipher (user password).
     * @param salt   The salt for the key schedule.
     * @param rounds The number of rounds (determined by the cost parameter in Bcrypt).
     */
    public void eksKeySchedule(byte[] key, byte[] salt, int rounds) {
        int keyLen = key.length;
        int offset = 0;

        for (int i = 0; i < P.length; i++) {
            int data = 0;
            for (int j = 0; j < 4; j++) {
                data = (data << 8) | (key[offset] & 0xff);
                offset = (offset + 1) % keyLen;
            }
            P[i] ^= data;
        }

        byte[] block = new byte[8];
        for (int i = 0; i < P.length; i += 2) {
            mixBlock(block, salt);
            int[] lr = encryptBlock(block);
            P[i] = lr[0];
            P[i + 1] = lr[1];
        }

        for (int i = 0; i < S.length; i += 2) {
            mixBlock(block, salt);
            int[] lr = encryptBlock(block);
            S[i] = lr[0];
            S[i + 1] = lr[1];
        }

        for (int r = 0; r < rounds; r++) {
            keySchedule(key);
            keySchedule(salt);
        }
    }

    /**
     * Encrypts a block of data in ECB mode.
     *
     * @param data The input data to encrypt (must be a multiple of 8 bytes).
     * @return The encrypted data.
     */
    public byte[] encryptECB(byte[] data) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i += 8) {
            int[] lr = encryptBlock(Arrays.copyOfRange(data, i, i + 8));
            encodeInt(result, i, lr[0]);
            encodeInt(result, i + 4, lr[1]);
        }
        return result;
    }

    /**
     * Encrypts an 8-byte block using the Blowfish cipher.
     *
     * @param block The 8-byte input block.
     * @return An array containing the encrypted left and right halves.
     */
    private int[] encryptBlock(byte[] block) {
        int left = decodeInt(block, 0);
        int right = decodeInt(block, 4);

        for (int i = 0; i < 16; i++) {
            left ^= P[i];
            right ^= round(left);
            int temp = left;
            left = right;
            right = temp;
        }

        int temp = left;
        left = right;
        right = temp;

        right ^= P[16];
        left ^= P[17];
        return new int[]{left, right};
    }

    /**
     * Processes a single round of the Blowfish cipher.
     *
     * @param x The input value.
     * @return The result of the Blowfish round function.
     */
    private int round(int x) {
        int h = S[(x >>> 24) & 0xff] + S[0x100 | ((x >>> 16) & 0xff)];
        h ^= S[0x200 | ((x >>> 8) & 0xff)];
        h += S[0x300 | (x & 0xff)];
        return h;
    }

    /**
     * Decodes a 4-byte integer from a byte array at the specified offset.
     *
     * @param data   The byte array.
     * @param offset The offset where the integer starts.
     * @return The decoded integer.
     */
    private static int decodeInt(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24)
             | ((data[offset + 1] & 0xff) << 16)
             | ((data[offset + 2] & 0xff) << 8)
             | (data[offset + 3] & 0xff);
    }

    /**
     * Encodes an integer into a byte array at the specified offset.
     *
     * @param data   The byte array to encode into.
     * @param offset The offset where the integer starts.
     * @param value  The integer value to encode.
     */
    private static void encodeInt(byte[] data, int offset, int value) {
        data[offset]     = (byte)((value >>> 24) & 0xff);
        data[offset + 1] = (byte)((value >>> 16) & 0xff);
        data[offset + 2] = (byte)((value >>> 8) & 0xff);
        data[offset + 3] = (byte)(value & 0xff);
    }

    /**
     * Mixes the block with the provided data (key or salt).
     * Used during the key schedule process.
     *
     * @param block The block to mix.
     * @param data  The data to mix in.
     */
    private void mixBlock(byte[] block, byte[] data) {
        for (int i = 0; i < 8; i++) {
            block[i] = data[i % data.length];
        }
    }

    /**
     * Performs the key schedule routine with the provided data.
     * Updates the P-array and S-boxes.
     *
     * @param data The data to use for the key schedule (key or salt).
     */
    private void keySchedule(byte[] data) {
        byte[] block = new byte[8];
        for (int i = 0; i < P.length; i += 2) {
            mixBlock(block, data);
            int[] lr = encryptBlock(block);
            P[i] = lr[0];
            P[i + 1] = lr[1];
        }

        for (int i = 0; i < S.length; i += 2) {
            mixBlock(block, data);
            int[] lr = encryptBlock(block);
            S[i] = lr[0];
            S[i + 1] = lr[1];
        }
    }
}