/**
 * 
 */
package com.jbote.crypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;

/**
 * @author jobert
 * 
 */
public interface IEncryptionIO {
	/**
	 * Encrypt the contents from path to output.
	 * 
	 * @param path
	 * @param out
	 * @throws Exception
	 */
	void encrypt(Path path, OutputStream out) throws Exception;

	/**
	 * Read the input stream and write the encrypted data to output stream.
	 * 
	 * @param in
	 * @param out
	 * @throws Exception
	 */
	void encrypt(InputStream in, OutputStream out) throws Exception;

	/**
	 * Decrypt the contents from path to output.
	 * 
	 * @param path
	 * @param out
	 * @param passphrase
	 * @throws Exception
	 */
	void decrypt(Path inpath, OutputStream out, String passphrase) throws Exception;

	/**
	 * Read the encrypted data from input stream and write the decrypted data to
	 * output stream.
	 * 
	 * @param in
	 * @param out
	 * @param passphrase
	 * @throws Exception
	 */
	void decrypt(InputStream in, OutputStream out, String passphrase) throws Exception;
}
