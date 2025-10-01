/**
 * 
 */
package com.jbote.crypto;

/**
 * @author jobert
 * 
 */
public interface IPasswordHash extends IEncryption {
	/**
	 * Check if the given plain text password matches the hashed password.
	 * 
	 * @param password
	 * @param passwordHash
	 * @return
	 */
	boolean matches(String password, String hashedPassword);
}
