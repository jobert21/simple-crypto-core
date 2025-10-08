package com.jbote.crypto.impl;

import static com.jbote.crypto.utils.EncryptionUtils.DEFAULT_ALGORITHM;
import static com.jbote.crypto.utils.EncryptionUtils.DEFAULT_FIPS_PROVIDER;
import static com.jbote.crypto.utils.EncryptionUtils.DEFAULT_HOME;
import static com.jbote.crypto.utils.EncryptionUtils.PRIVATE_KEY_NAME;
import static com.jbote.crypto.utils.EncryptionUtils.PUBLIC_KEY_NAME;

import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jbote.crypto.IEncryption;
import com.jbote.crypto.IEncryptionKey;

/**
 * 
 * @author jobert
 *
 */
public class RSAEncryption implements IEncryption, IEncryptionKey {
	private static final Logger log = LoggerFactory.getLogger(RSAEncryption.class);
	private Path encryptHome;
	private String password;
	private Cipher decryptCipher;
	private Cipher encryptCipher;

	public RSAEncryption() {
		this(Paths.get(System.getProperty("user.home"), DEFAULT_HOME));
	}

	public RSAEncryption(Path encryptHome) {
		this.encryptHome = encryptHome != null ? encryptHome : Paths.get(System.getProperty("user.home"), DEFAULT_HOME);
		log.debug("Loading RSA keys from {}.", this.encryptHome);
		if (!Files.exists(this.encryptHome)) {
			try {
				Files.createDirectories(this.encryptHome);
			} catch (IOException e) {
			}
		}
	}

	@Override
	public Path generateKeys(String algorithm) {
		return generateKeys(algorithm, UUID.randomUUID().toString());
	}

	@Override
	public Path generateKeys(String algorithm, String password) {
		this.password = password;
		if (!Files.exists(encryptHome)) {
			try {
				Files.createDirectories(encryptHome);
			} catch (IOException e) {
				throw new RuntimeException("Unable to create directory " + encryptHome);
			}
		}
		try {
			Path pubKey = encryptHome.resolve(PUBLIC_KEY_NAME);
			Path privKey = encryptHome.resolve(PRIVATE_KEY_NAME);
			if (!Files.exists(pubKey) || !Files.exists(privKey)) {
				log.info("RSA keys does not exist. Create and save to {}.", encryptHome);
				KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, DEFAULT_FIPS_PROVIDER);
				kpg.initialize(4096);

				KeyPair kp = kpg.genKeyPair();
				PublicKey publicKey = kp.getPublic();
				savePublicKeyFile(encryptHome, PUBLIC_KEY_NAME, publicKey);

				PrivateKey privateKey = kp.getPrivate();
				savePrivateKeyFile(encryptHome, PRIVATE_KEY_NAME, password, privateKey);
			}
			log.debug("CIPHER: Using RSA keys from {}, {}", pubKey, privKey);
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
		return encryptHome;
	}

	protected void savePublicKeyFile(Path keysPath, String fileName, PublicKey publicKey) throws Exception {
		PemObject pemObject = new PemObject("PUBLIC KEY", publicKey.getEncoded());

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(out));
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		saveFile(keysPath, fileName, out.toByteArray());
	}

	protected void savePrivateKeyFile(Path keysPath, String filename, String password, PrivateKey privateKey)
			throws Exception {
		JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
				PKCS8Generator.PBE_SHA1_3DES);
		encryptorBuilder.setRandom(new SecureRandom());
		encryptorBuilder.setPassword(password.toCharArray());
		OutputEncryptor oe = encryptorBuilder.build();
		JcaPKCS8Generator gen = new JcaPKCS8Generator(privateKey, oe);
		PemObject pemObject = gen.generate();

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(out));
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		saveFile(keysPath, PRIVATE_KEY_NAME, out.toByteArray());
	}

	protected void saveFile(Path keysPath, String fileName, byte[] encoded) throws IOException {
		Path filePath = keysPath.resolve(fileName);
		if (!Files.exists(filePath)) {
			Files.createFile(filePath);
		}

		OutputStream out = null;
		try {
			out = Files.newOutputStream(filePath);
			out.write(encoded);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			if (out != null) {
				out.flush();
				out.close();
			}
		}
	}

	protected Path getPath(String fileName) {
		Path path = encryptHome.resolve(fileName);
		return path;
	}

	protected byte[] readKey(Path keyPath) throws Exception {
		PemReader reader = null;
		try {
			reader = new PemReader(new InputStreamReader(Files.newInputStream(keyPath)));
			PemObject object = reader.readPemObject();
			return object.getContent();
		} finally {
			if (reader != null) {
				reader.close();
			}
		}
	}

	@Override
	public byte[] encrypt(byte[] contents) throws Exception {
		try {			
			byte[] cipherText = getEncryptCipher().doFinal(contents);
			return cipherText;
		} catch (Exception e) {
			if (log.isDebugEnabled()) {
				log.warn("CIPHER: Unable to encrypt contents.");
			}
			throw new Exception("Unable to encrypt contents.", e);
		}
	}

	@Override
	public byte[] decrypt(byte[] contents) throws Exception {
		try {
			byte[] decrypted = getDecryptCipher().doFinal(contents);
			return decrypted != null ? decrypted : null;
		} catch (Exception e) {
			if (log.isDebugEnabled()) {
				log.warn("CIPHER: Unable to decrypt contents");
			}
			throw new Exception("Unable to decrypt contents.", e);
		}
	}

	private Cipher getEncryptCipher() throws Exception {
		if (encryptCipher == null) {
			Path pubKey = getPath(PUBLIC_KEY_NAME);
			if (!Files.exists(pubKey)) {
				throw new Exception(PUBLIC_KEY_NAME + " does not exist. Please generate RSA keys.");
			}
			byte[] pemContent = readKey(pubKey);

			X509EncodedKeySpec spec = new X509EncodedKeySpec(pemContent);
			KeyFactory kf = KeyFactory.getInstance(DEFAULT_ALGORITHM);
			PublicKey publicKey = (PublicKey) kf.generatePublic(spec);

			encryptCipher = Cipher.getInstance(DEFAULT_ALGORITHM);
			encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		}
		return encryptCipher;
	}

	private Cipher getDecryptCipher() throws Exception {
		if (decryptCipher == null) {
			Path privPath = getPath(PRIVATE_KEY_NAME);
			if (!Files.exists(privPath)) {
				throw new Exception(PRIVATE_KEY_NAME + " does not exist. Please generate RSA keys.");
			}
			char[] passArray = password.toCharArray();

			PEMParser pemParser = null;
			try {
				pemParser = new PEMParser(new FileReader(privPath.toFile()));
				Object object = pemParser.readObject();
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BCFIPS");

				PrivateKey privateKey = null;
				if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
					InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passArray);
					PKCS8EncryptedPrivateKeyInfo keyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
					PrivateKeyInfo pkInfo = keyInfo.decryptPrivateKeyInfo(provider);
					privateKey = converter.getPrivateKey(pkInfo);
				} else {
					PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(passArray);
					KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
					privateKey = keyPair.getPrivate();
				}
				decryptCipher = Cipher.getInstance(DEFAULT_ALGORITHM);
				decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
			} catch (Exception ex) {
				throw ex;
			} finally {
				if (pemParser != null) {
					pemParser.close();
				}
			}
		}
		return decryptCipher;
	}

}
