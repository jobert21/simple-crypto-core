/**
 * 
 */
package com.jbote.crypto;

import java.nio.file.Path;
import java.util.Objects;

import com.jbote.crypto.impl.PBKDF2PasswordHash;
import com.jbote.crypto.impl.RSAEncryption;
import com.jbote.crypto.impl.Sha3PasswordHash;
import com.jbote.crypto.utils.EncryptionUtils;

/**
 * @author jobert
 * 
 */
public class CryptoBuilder {
	public static RSABuilder rsa() {
		return new RSABuilder();
	}

	public static PBKDF2PasswordHashBuilder pbkdf2Hash() {
		return new PBKDF2PasswordHashBuilder();
	}

	public static Sha3PasswordHashBuilder sha3Hash() {
		return new Sha3PasswordHashBuilder();
	}

	public static class PBKDF2PasswordHashBuilder {
		private static int MIN_ITERATIONS = 10000;
		private int iterations;

		public PBKDF2PasswordHashBuilder() {
			iterations = PBKDF2PasswordHash.PBKDF2_ITERATIONS;
		}

		public PBKDF2PasswordHashBuilder setIterations(int iterations) {
			this.iterations = iterations;
			return this;
		}

		public IPasswordHash build() {
			return new PBKDF2PasswordHash(iterations >= MIN_ITERATIONS ? iterations : MIN_ITERATIONS);
		}
	}

	public static class Sha3PasswordHashBuilder {
		public IPasswordHash build() {
			return new Sha3PasswordHash();
		}
	}

	public static class RSABuilder {
		private String password;
		private Path keysHome;

		public String getPassword() {
			return password;
		}

		public RSABuilder setPassword(String password) {
			this.password = password;
			return this;
		}

		public Path getKeysHome() {
			return keysHome;
		}

		public RSABuilder setKeysHome(Path keysHome) {
			this.keysHome = keysHome;
			return this;
		}

		public IEncryption build() {
			Objects.requireNonNull(password, "RSA password is required.");
			RSAEncryption rsaEnc = new RSAEncryption(keysHome);
			rsaEnc.generateKeys(EncryptionUtils.DEFAULT_ALGORITHM, password);
			return rsaEnc;
		}
	}
}
