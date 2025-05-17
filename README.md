# bcrypt-ultimate

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java Version](https://img.shields.io/badge/Java-23%2B-blue)](https://www.oracle.com/java/technologies/javase-downloads.html)

---

**bcrypt-ultimate** is a modern and secure Java library for password hashing using the Bcrypt algorithm, with optional pre-processing using key derivation functions (KDFs) like Argon2 or HKDF.

---

## 🎯 Purpose

This library optionally applies a KDF (like Argon2id or HKDF) before bcrypt, to increase the security of the password hashing process.

Its main goals are:

- **Bypass bcrypt’s 72-byte password input limit.**
- **Increase resistance to GPU/ASIC attacks** with memory-hard KDFs.
- Provide **modularity and flexibility** in how passwords are processed and hashed.

> Note: This library is not intended as a full cryptographic KDF for key material (e.g., AES). Its focus is secure and customizable **password hashing workflows**.

---

## ✨ Features

* ✅ Pure Java Bcrypt (no native bindings)
* ✅ Secure EksBlowfish cipher with OpenBSD Base64
* ✅ Optional key derivation function (KDF) pre-processing (e.g., Argon2id, HKDF)
* ✅ Fluent & type-safe builder pattern
* ✅ Thread-safe core (`@ThreadSafe`)
* ✅ CLI for password hashing & verification
* ✅ Security enhancements:
  * Constant-time comparison to prevent timing attacks
  * Cryptographically secure random salts
  * Strict FIPS-compliant mode
  * Support for Bcrypt versions: $2a$, $2b$, and $2y$ (with $2a$ and $2y$ internally mapped to $2b$ for compatibility with standard implementations)

---

## 🔐 Why KDF Before Bcrypt?

Bcrypt has a known limitation: it only uses the first 72 bytes of a password. Any characters beyond that are ignored.

By applying a KDF (e.g., Argon2id, HKDF) **before** passing the password to bcrypt, you:

- Avoid bcrypt’s truncation behavior
- Normalize passwords to a fixed, secure length
- Add computational or memory-based protection (depending on the KDF)

This approach offers better defense against brute-force and side-channel attacks.

---

## 🚀 Getting Started

### Prerequisites

* Java 23+
* Maven 3.9+

### Build

```bash
git clone https://github.com/6pheR/bcrypt-ultimate.git
cd bcrypt-ultimate
mvn clean install
```

### Output

* `target/bcrypt-ultimate-1.0.0.jar` – core library
* `target/bcrypt-ultimate-1.0.0-fat.jar` – runnable standalone JAR

---

## 🔧 CLI Usage

```bash
 -c,--cost <arg>        Cost factor (default: 12)
 -h,--hash              Hash a password
 -H,--hashvalue <arg>   Hashed value to verify against
 -k,--kdf               Use Argon2 key derivation
 -p,--password <arg>    Password to hash or verify
 -s,--strict            Enable strict FIPS mode
 -v,--verify            Verify a password
```

### Hash

```bash
java -jar bcrypt-ultimate.jar --hash --password "myPassword123" --cost 12
```

### Verify

```bash
java -jar bcrypt-ultimate.jar --verify --password "myPassword123" --hashvalue "$2b$12$...."
```

---

## 🧪 Programmatic Usage

### Basic Hash

```java
String hash = BcryptEngine.hash("password", BcryptConfig.builder()
    .setCostFactor(12)
    .build(), new SecureRandom());
```

### With Argon2 KDF

```java
BcryptConfig config = BcryptConfig.builder()
    .setCostFactor(12)
    .withKdf(Argon2KdfEngine.builder()
        .timeCost(3)
        .memoryCost(65536)
        .parallelism(2)
        .hashLength(32)
        .build())
    .build();

String hash = BcryptEngine.hash("password", config, new SecureRandom());
```

### With HKDF

```java
BcryptConfig config = BcryptConfig.builder()
    .setCostFactor(12)
    .withKdf(new HkdfEngine())
    .build();
```

### Custom Bcrypt Version

```java
BcryptConfig config = BcryptConfig.builder()
    .setCostFactor(12)
    .setVersion("2y")
    .build();
```

### Verify Password

```java
boolean valid = BcryptEngine.verify("password", hash, config);
```

---

## ✅ Test Coverage

```bash
mvn test
```

Test suites:

- `BcryptTest` → Core functionality
- `KdfEngineTest` → Argon2 & HKDF
- `BcryptAdvancedTest` → Timing consistency, edge cases
- `BcryptCliTest` → CLI integration
- `BcryptVersionTest` → Test versions `$2a$`, `$2b$`, `$2y$`

All tests: ✔ Passed

---

## 📁 Project Structure

```text
src/
 ├── main/java/fr/cipher/bcrypt
 │   ├── core/       → Bcrypt engine (EksBlowfish, Blowfish)
 │   ├── kdf/        → Argon2 & HKDF implementations
 │   ├── util/       → Encoders, comparators
 │   └── cli/        → CLI interface
 └── test/java/...   → JUnit test classes
```

---

## ⚠ Caveats

* Not officially FIPS-certified
* Bcrypt is CPU-bound, not ideal for large files
* Use with Argon2 or HKDF for modern systems
* Bcrypt limits passwords to 72 bytes. Any characters beyond that are ignored.  
To avoid unexpected behavior, it's recommended to pre-process passwords using a KDF such as Argon2 or HKDF.

---

## 📄 License

MIT © [6pheR](https://github.com/6pheR)

---

## 🤝 Contributions

Issues and pull requests welcome!

---

## 🙌 Acknowledgments

* Based on the original OpenBSD Bcrypt spec
* Argon2 via [Jargon2](https://github.com/kosprov/jargon2-api)
* Inspired by [BCrypt.Net](https://github.com/BcryptNet/bcrypt.net)

---

✌️ Happy hashing!
