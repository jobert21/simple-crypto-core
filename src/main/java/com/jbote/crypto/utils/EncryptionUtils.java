/**
 * 
 */
package com.jbote.crypto.utils;

import java.math.BigInteger;

/**
 * @author jobert
 * 
 */
public class EncryptionUtils {
	public static final String PUBLIC_KEY_NAME = "id_rsa.pub";
	public static final String PRIVATE_KEY_NAME = "id_rsa";
	public static final String DEFAULT_ALGORITHM = "RSA";
	public static final String DEFAULT_FIPS_PROVIDER = "BCFIPS";
	public static final String DEFAULT_HOME = ".encryption_keys";

	public static String toHex(byte[] array) {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0)
			return String.format("%0" + paddingLength + "d", 0) + hex;
		else
			return hex;
	}

	public static byte[] fromHex(String hex) {
		byte[] binary = new byte[hex.length() / 2];
		for (int i = 0; i < binary.length; i++)
			binary[i] = (byte) Integer.parseInt(hex.substring(2 * i, (2 * i) + 2), 16);
		return binary;
	}

	public static boolean slowEquals(byte[] a, byte[] b) {
		int diff = a.length ^ b.length;
		for (int i = 0; (i < a.length) && (i < b.length); i++)
			diff |= a[i] ^ b[i];
		return diff == 0;
	}
}
