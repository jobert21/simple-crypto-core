package com.jbote.crypto;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Base64;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class RSATest {
	static IEncryption rsa;
	static Path encryptHome;
	
	@BeforeClass
	public static void beforeClass() {
		encryptHome = Paths.get(System.getProperty("user.home"), "rsa-test");
		
		rsa = CryptoBuilder
				.rsa()
				.setKeysHome(encryptHome)
				.setPassword("12345")
				.build();
		
	}
	
	@AfterClass
	public static void afterClass() throws Exception {
		try {
			Files.walkFileTree(encryptHome, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					Files.deleteIfExists(file);
					return FileVisitResult.CONTINUE;
				}
			});
		} catch (Exception e) {
		}
	}
	
	@Test
	public void testEncrypt() throws Exception {
		String contents = "hello world!";
		byte[] encrypted = rsa.encrypt("hello world!".getBytes());
		Assert.assertNotNull(encrypted);
		
		byte[] decrypted = rsa.decrypt(encrypted);
		Assert.assertNotNull(decrypted);
		Assert.assertEquals(contents, new String(decrypted));
	}
	
	@Test 
	public void testEncryptDecryptWithBase64() throws Exception {
		String contents = "hello world!";
		byte[] encrypted = rsa.encrypt("hello world!".getBytes());
		Assert.assertNotNull(encrypted);
		
		byte[] encoded = Base64.getEncoder().encode(encrypted);
		
		byte[] decoded = Base64.getDecoder().decode(encoded);
		Assert.assertArrayEquals(encrypted, decoded);
		
		byte[] decrypted = rsa.decrypt(decoded);
		Assert.assertEquals(contents, new String(decrypted));
	}
}
