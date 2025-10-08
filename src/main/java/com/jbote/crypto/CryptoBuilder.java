/**
 * 
 */
package com.jbote.crypto;

import java.nio.file.Path;
import java.security.Security;
import java.util.Objects;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import com.jbote.crypto.impl.PBKDF2PasswordHash;
import com.jbote.crypto.impl.PGPEncryption;
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
	
	public static PGPBuilder pgp() {
		return new PGPBuilder();
	}

	public static class PGPBuilder {
		private Path keysHomeDirectory;
		private String keyPrefix;
		private boolean generateKeys;
		private String keyPassphrase;

		public PGPBuilder() {

		}

		public PGPBuilder setKeysHomeDirectory(Path keysHomeDirectory) {
			this.keysHomeDirectory = keysHomeDirectory;
			return this;
		}

		public PGPBuilder setKeyPrefix(String keyPrefix) {
			this.keyPrefix = keyPrefix;
			return this;
		}

		public PGPBuilder generateKeys() {
			this.generateKeys = true;
			return this;
		}

		public PGPBuilder setKeyPassphrase(String keyPassphrase) {
			this.keyPassphrase = keyPassphrase;
			return this;
		}

		public IEncryptionIO build() {
			if (keysHomeDirectory == null) {
				throw new RuntimeException("Must specify the keys directory.");
			}
			if (generateKeys) {
				if (keyPassphrase == null || keyPassphrase.trim().isEmpty()) {
					throw new RuntimeException("Key passphrase is required to generate keys.");
				}
			}
			Security.addProvider(new BouncyCastleFipsProvider());
			PGPEncryption pgp = new PGPEncryption(keysHomeDirectory, keyPrefix, generateKeys, keyPassphrase);
			return pgp;
		}
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
		private Path keysHomeDirectory;

		public String getPassword() {
			return password;
		}

		public RSABuilder setPassword(String password) {
			this.password = password;
			return this;
		}

		public RSABuilder setKeysHomeDirectory(Path keysHomeDirectory) {
			this.keysHomeDirectory = keysHomeDirectory;
			return this;
		}

		public IEncryption build() {
			Security.addProvider(new BouncyCastleFipsProvider());
			Objects.requireNonNull(password, "RSA password is required.");
			RSAEncryption rsaEnc = new RSAEncryption(keysHomeDirectory);
			rsaEnc.generateKeys(EncryptionUtils.DEFAULT_ALGORITHM, password);
			return rsaEnc;
		}
	}
}
