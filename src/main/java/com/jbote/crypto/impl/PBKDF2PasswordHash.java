/**
 * 
 */
package com.jbote.crypto.impl;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.jbote.crypto.IPasswordHash;
import com.jbote.crypto.utils.EncryptionUtils;

/**
 * @author jobert
 * 
 */
public class PBKDF2PasswordHash implements IPasswordHash {
	public static final int SALT_BYTES = 24;
	public static final int HASH_BYTES = 24;
	public static final int PBKDF2_ITERATIONS = 310000;

	public static final int ITERATION_INDEX = 0;
	public static final int SALT_INDEX = 1;
	public static final int PBKDF2_INDEX = 2;
	private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
	private SecureRandom random;
	private int iterations;

	public PBKDF2PasswordHash() {
		this(PBKDF2_ITERATIONS);
	}
	
	public PBKDF2PasswordHash(int iterations) {
		this.iterations = iterations;
		random = new SecureRandom();
	}

	@Override
	public byte[] encrypt(byte[] contents) throws Exception {
		byte[] salt = new byte[SALT_BYTES];
		random.nextBytes(salt);
		byte[] digest = pbkdf2(new String(contents).toCharArray(), salt, iterations, HASH_BYTES);
		return String.format("%s:%s:%s", iterations, EncryptionUtils.toHex(salt), EncryptionUtils.toHex(digest))
				.getBytes();
	}

	@Override
	public byte[] decrypt(byte[] contents) throws Exception {
		throw new Exception("Decrypt not supported in password hash.");
	}

	@Override
	public boolean matches(String password, String hashedPassword) {
		String[] params = hashedPassword.split(":");
		int iterations = Integer.parseInt(params[ITERATION_INDEX]);
		byte[] hash = EncryptionUtils.fromHex(params[PBKDF2_INDEX]);
		byte[] salt = EncryptionUtils.fromHex(params[SALT_INDEX]);
		boolean match = false;
		try {
			byte[] digest = pbkdf2(password.toCharArray(), salt, iterations, hash.length);
			match = EncryptionUtils.slowEquals(hash, digest);
		} catch (Exception e) {
		}

		return match;
	}

	private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
		return skf.generateSecret(spec).getEncoded();
	}
}
