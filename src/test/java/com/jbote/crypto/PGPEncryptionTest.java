/**
 * 
 */
package com.jbote.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author jobert
 * 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PGPEncryptionTest {
	static IEncryptionIO pgp;
	static Path keysHome;
	static Path testFile;
	static String testPassphrase;

	@BeforeClass
	public static void beforeClass() throws Exception {
		keysHome = Paths.get(System.getProperty("user.home")).resolve("pgp-test");
		if (!Files.exists(keysHome)) {
			Files.createDirectories(keysHome);
		} else {
			clearDir(keysHome);
		}
		InputStream in = PGPEncryptionTest.class.getResourceAsStream("/test.txt");
		testFile = keysHome.resolve("test.txt");
		Files.copy(in, testFile);
		pgp = CryptoBuilder
				.pgp()
				.setKeyPassphrase(testPassphrase = "1234")
				.setKeysHomeDirectory(keysHome)
				.generateKeys()
				.build();
	}

	@AfterClass
	public static void afterClass() throws Exception {
		clearDir(keysHome);
	}

	@Test
	public void test1Encrypt() throws Exception {
		Path encrypted = keysHome.resolve("test.txt.enc");
		try (OutputStream out = Files.newOutputStream(encrypted)) {
			pgp.encrypt(testFile, out);
		}
	}
	
	@Test
	public void test2Decrypt() throws Exception {
		Path encrypted = keysHome.resolve("test.txt.enc");
		Path decrypted = keysHome.resolve("test.txt.dec");
		try (OutputStream out = Files.newOutputStream(decrypted)) {
			pgp.decrypt(encrypted, out, testPassphrase);
		}
		
		String decryptedContents = new String(Files.readAllBytes(decrypted));
		String contents = new String(Files.readAllBytes(testFile));
		Assert.assertEquals(contents, decryptedContents);
	}

	private static void clearDir(Path start) throws Exception {
		Files.walkFileTree(start, new SimpleFileVisitor<Path>() {
			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				Files.deleteIfExists(file);
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
				if (!dir.equals(start)) {
					Files.deleteIfExists(dir);
				}
				return FileVisitResult.CONTINUE;
			}
		});
	}
}
