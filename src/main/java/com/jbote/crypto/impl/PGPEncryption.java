/**
 * 
 */
package com.jbote.crypto.impl;

import static com.jbote.crypto.utils.EncryptionUtils.DEFAULT_FIPS_PROVIDER;
import static com.jbote.crypto.utils.EncryptionUtils.DEFAULT_ALGORITHM;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jbote.crypto.IEncryptionIO;

/**
 * @author jobert
 * 
 */
public class PGPEncryption implements IEncryptionIO {
	private static final Logger log = LoggerFactory.getLogger(PGPEncryption.class);
	private PGPEncryptionKey encryptionKey;

	public PGPEncryption(Path home, String keyPrefix, boolean generateKeys, String keyPassphrase) {
		this.encryptionKey = new PGPEncryptionKey(home, keyPrefix);
		if (generateKeys) {
			this.encryptionKey.generateKeys(DEFAULT_ALGORITHM, keyPassphrase);
		}
	}

	@Override
	public void encrypt(Path path, OutputStream out) throws Exception {
		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
						.setProvider(DEFAULT_FIPS_PROVIDER));
		PGPPublicKey encKey = encryptionKey.getPublicKey();
		encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(DEFAULT_FIPS_PROVIDER));
		try (OutputStream encOut = encGen.open(out, Files.size(path)); InputStream in = Files.newInputStream(path)) {
			IOUtils.copy(in, encOut);
		}
		log.info("{} encrypted.", path);
	}

	@Override
	public void decrypt(Path path, OutputStream out, String passphrase) throws Exception {
		try (InputStream keyIn = PGPUtil.getDecoderStream(Files.newInputStream(encryptionKey.getPrivateKeyPath()));
				InputStream in = PGPUtil.getDecoderStream(Files.newInputStream(path))) {

			PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(keyIn,
					new JcaKeyFingerprintCalculator());
			PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
			Object o = pgpF.nextObject();
			if (!(o instanceof PGPEncryptedDataList)) {
				o = pgpF.nextObject();
			}
			PGPEncryptedDataList encList = (PGPEncryptedDataList) o;

			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;

			for (PGPEncryptedData ed : encList) {
				PGPPublicKeyEncryptedData pked = (PGPPublicKeyEncryptedData) ed;
				PGPSecretKey sk = pgpSec.getSecretKey(pked.getKeyIdentifier().getKeyId());
				if (sk != null) {
					sKey = sk.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(DEFAULT_FIPS_PROVIDER)
							.build(passphrase.toCharArray()));
					pbe = pked;
					break;
				}
			}
			if (sKey == null) {
				throw new IllegalArgumentException("Secret key not found.");
			}
			try (InputStream clear = pbe.getDataStream(
					new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(DEFAULT_FIPS_PROVIDER).build(sKey))) {
				IOUtils.copy(clear, out);
			}
			log.info("{} decrypted.", path);
		}
	}

}
