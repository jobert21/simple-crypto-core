/**
 * 
 */
package com.jbote.crypto.impl;

import static com.jbote.crypto.utils.EncryptionUtils.DEFAULT_FIPS_PROVIDER;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jbote.crypto.IEncryptionKey;

/**
 * @author jobert
 * 
 */
public class PGPEncryptionKey implements IEncryptionKey {
	private static final Logger log = LoggerFactory.getLogger(PGPEncryptionKey.class);
	private static final int DEFAULT_KEY_SIZE = 4096;
	private Path home;
	private String prefix;
	private String password;

	public PGPEncryptionKey() {
		this(Paths.get(System.getProperty("user.home")));
	}

	public PGPEncryptionKey(Path home) {
		this(home, null);
	}

	public PGPEncryptionKey(Path home, String prefix) {
		this.home = home;
		this.prefix = prefix != null && !prefix.trim().isEmpty() ? (prefix + "_") : "";

		if (!Files.exists(home)) {
			try {
				Files.createDirectories(home);
			} catch (Exception e) {
			}
		}
	}
	
	public Path getPublicKeyPath() {
		return home.resolve(prefix + "public.pub");
	}
	
	public Path getPrivateKeyPath() {
		return home.resolve(prefix + "private.pub");
	}
	
	public PGPPublicKey getPublicKey() throws Exception {
		PGPPublicKey encKey = null;
		try (InputStream in = PGPUtil.getDecoderStream(Files.newInputStream(getPublicKeyPath()))) {
			PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
			for (PGPPublicKeyRing keyRing : pubRings) {
				for (PGPPublicKey key : keyRing) {
					if (key.isEncryptionKey()) {
						encKey = key;
						break;
					}
				}
			}
		}

		return encKey;
	}
	
	@Override
	public Path generateKeys(String algorithm) {
		return generateKeys(algorithm, UUID.randomUUID().toString());
	}

	@Override
	public Path generateKeys(String algorithm, String password) {
		try {
			this.password = password;
			Path pub = getPublicKeyPath();
			Path priv = getPrivateKeyPath();
			if (!Files.exists(pub) || !Files.exists(priv)) {
				KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, DEFAULT_FIPS_PROVIDER);
				kpg.initialize(DEFAULT_KEY_SIZE);

				KeyPairGenerator kpg2 = KeyPairGenerator.getInstance(algorithm, DEFAULT_FIPS_PROVIDER);
				kpg2.initialize(DEFAULT_KEY_SIZE);

				PGPKeyPair master = new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());
				PGPKeyPair enc = new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PGPPublicKey.RSA_GENERAL, kpg2.generateKeyPair(), new Date());

				JcaPGPContentSignerBuilder signBuilder = new JcaPGPContentSignerBuilder(
						master.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256).setProvider(DEFAULT_FIPS_PROVIDER);

				JcePBESecretKeyEncryptorBuilder secretEncryptorBuilder = new JcePBESecretKeyEncryptorBuilder(
						SymmetricKeyAlgorithmTags.AES_256, new JcaPGPDigestCalculatorProviderBuilder()
								.setProvider(DEFAULT_FIPS_PROVIDER).build().get(HashAlgorithmTags.SHA256))
						.setProvider(DEFAULT_FIPS_PROVIDER);
				
				PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
		                PGPSignature.POSITIVE_CERTIFICATION,
		                master,
		                UUID.randomUUID().toString(),
		                new JcaPGPDigestCalculatorProviderBuilder().setProvider(DEFAULT_FIPS_PROVIDER).build().get(HashAlgorithmTags.SHA1),
		                null,
		                null,
		                signBuilder,
		                secretEncryptorBuilder.build(password.toCharArray())
		        );
				keyRingGen.addSubKey(enc);
				try (OutputStream pubOut = new ArmoredOutputStream(Files.newOutputStream(pub));
						OutputStream secOut = new ArmoredOutputStream(Files.newOutputStream(priv))) {

					PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
					PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

					pubRing.encode(pubOut);
					secRing.encode(secOut);
				}
				log.info("PGP keys generated. {} , {}", pub, priv);
			}
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
		return home;
	}
	
	public String getPassword() {
		return password;
	}
}
