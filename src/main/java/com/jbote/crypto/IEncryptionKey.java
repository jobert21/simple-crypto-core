package com.jbote.crypto;

import java.nio.file.Path;

/**
 * 
 * @author jobert
 *
 */
public interface IEncryptionKey {
	/**
	 * Generate keys.
	 * 
	 * @param algorithm
	 * @return
	 */
	Path generateKeys(String algorithm);

	/**
	 * Generate keys to the given path.
	 * 
	 * @param algorithm
	 * @param password
	 * @return
	 */
	Path generateKeys(String algorithm, String password);
}
