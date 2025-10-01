package com.jbote.crypto;

/**
 * 
 * @author jobert
 *
 */
public interface IEncryption {
	/**
	 * Encrypt the contents.
	 * 
	 * @param contents
	 * @return
	 */
	byte[] encrypt(byte[] contents) throws Exception;

	/**
	 * Decrypt contents.
	 * 
	 * @param contents
	 * @return
	 * @throws Exception
	 */
	byte[] decrypt(byte[] contents) throws Exception;
}
