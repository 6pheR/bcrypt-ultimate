package fr.cipher.bcrypt.util;

/**
 * Utility to compare two byte arrays in constant time to prevent timing attacks.
 */
public final class ConstantTimeComparator {

	/**
	 * Private constructor to prevent instantiation of this utility class. This
	 * class is meant to provide static constants only.
	 */
    private ConstantTimeComparator() {}

    /**
     * Constant-time comparison between two byte arrays.
     *
     * @param a First array
     * @param b Second array
     * @return true if equal, false otherwise
     */
    public static boolean equals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }
}
