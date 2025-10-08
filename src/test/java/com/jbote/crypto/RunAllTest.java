package com.jbote.crypto;


import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({ RSATest.class, Sha3PasswordHashTest.class, PBKDF2PasswordHashTest.class, PGPEncryptionTest.class })
public class RunAllTest {
}
