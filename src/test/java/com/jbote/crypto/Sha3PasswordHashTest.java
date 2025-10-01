package com.jbote.crypto;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class Sha3PasswordHashTest {
	static IPasswordHash sha3Hash;

	@BeforeClass
	public static void beforeClass() {
		sha3Hash = CryptoBuilder.sha3Hash().build();
	}

	@Test
	public void testValidatePassword() throws Exception {
		String pwd = "test01";
		String hash1 = new String(sha3Hash.encrypt(pwd.getBytes()));
		Assert.assertTrue(sha3Hash.matches(pwd, hash1));
	}
}
