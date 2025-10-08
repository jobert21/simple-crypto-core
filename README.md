### Description

This library provides a simple builder for encryption. The following are supported

- SHA3-512, PBKDF2WithHmacSHA512 for hashing
- RSA (FIPS 140-3)
- PGP (FIPS 140-3)

### RSA
```
	IEncryption rsa = CryptoBuilder
				.rsa()
				.setKeysHomeDirectory(encryptHome)
				.setPassword("12345")
				.build();
	byte[] encrypted = rsa.encrypt("hello".getBytes());//not base64 encoded.
	byte[] decrypted = rsa.decrypt(encrypted);
```
### PGP
```
	IEncryptionIO pgp = CryptoBuilder
				.pgp()
				.setKeyPassphrase("1234")// required if generating keys.
				.setKeysHomeDirectory(keysHome)// the directory of the pgp keys
				.setKeyPrefix("hello") // use the prefix to generate the keys. e.g. "hello_public.pgp", "hello_private.pgp". if not specified, "public.pgp", "private.pgp"
				.generateKeys() // will generate keys. will be written in keys home directory.
				.build();
	Path clearPath = Paths.get("/path/to/file.txt");
	Path encryptedPath = Paths.get("/path/to/file.txt.encrypted");
	//encrypt
	try (OutputStream out = Files.newOutputStream(encryptedPath)) {
		pgp.encrypt(clearPath, out);
	}
	//decrypt
	Patch decryptPath = Paths.get("/path/to/file.decrypted.txt");
	try (OutputStream out = Files.newOutputStream(decryptPath)) {
		pgp.decrypt(encryptedPath, out, "1234");
	}
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