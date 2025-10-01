/**
 * 
 */
package com.jbote.crypto.impl;

import org.apache.commons.codec.digest.DigestUtils;

import com.jbote.crypto.IPasswordHash;
import com.jbote.crypto.utils.EncryptionUtils;

/**
 * @author jobert
 * 
 */
public class Sha3PasswordHash implements IPasswordHash {
	private static final String ALGORITHM = "SHA3-512";

	public Sha3PasswordHash() {
	}

	@Override
	public byte[] encrypt(byte[] contents) throws Exception {
		byte[] digest = new DigestUtils(ALGORITHM).digest(contents);
		return EncryptionUtils.toHex(digest).getBytes();
	}

	@Override
	public byte[] decrypt(byte[] contents) throws Exception {
		throw new Exception("Decrypt not supported in password hash.");
	}

	@Override
	public boolean matches(String password, String hashedPassword) {
		byte[] hash = EncryptionUtils.fromHex(hashedPassword);
		byte[] digest = new DigestUtils(ALGORITHM).digest(password);
		return EncryptionUtils.slowEquals(hash, digest);
	}

}
