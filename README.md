### Description

This library provides a simple builder for encryption. The following are supported

- SHA3-512, PBKDF2WithHmacSHA512 for hashing
- RSA

TODO: support FIPS 140-3 for PGP encryption

### Using the builder class
```
	IEncryption rsa = CryptoBuilder
				.rsa()
				.setKeysHome(encryptHome)
				.setPassword("12345")
				.build();
	byte[] encrypted = rsa.encrypt("hello".getBytes());//not base64 encoded.
	byte[] decrypted = rsa.decrypt(encrypted);
```

### To use the password hash
```
	IPasswordHash sha3 = CryptoBuilder
						.sha3Hash()
						.build();
	IPasswordHash pbkdf2 = CryptoBuilder
							.pbkdf2Hash()
							.setIterations(10000)
							.build();
	byte[] sha3Hash = sha3.encrypt("hello".getBytes());
	byte[] pbkdf2Hash = pbkdf2.encrypt("hello".getBytes());
	
	boolean match = sha3.matches("hello", new String(sha3Hash));
```