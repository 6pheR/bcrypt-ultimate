# bcrypt-ultimate

**bcrypt-ultimate** is a modern and secure Java library for password hashing using the Bcrypt algorithm, with optional pre-KDF support via Argon2 or HKDF.

---

## ✨ Features

* ✅ Pure Java Bcrypt (no native bindings)
* ✅ Secure EksBlowfish cipher with OpenBSD Base64
* ✅ Optional KDF pre-processing (Argon2 or HKDF)
* ✅ Fluent & type-safe builder pattern
* ✅ Thread-safe core (`@ThreadSafe`)
* ✅ CLI for password hashing & verification
* ✅ Security enhancements:
  * Constant-time comparison
  * SecureRandom salts
  * Strict FIPS-safe mode

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

### Hash

```bash
java -jar target/bcrypt-ultimate-1.0.0-fat.jar   --hash --password "myPassword123" --cost 12
```

### Verify

```bash
java -jar target/bcrypt-ultimate-1.0.0-fat.jar   --verify --password "myPassword123"   --hashvalue "$2b$12$...."
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
        .iterations(3)
        .memoryKb(65536)
        .parallelism(2)
        .outputLength(32)
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

### Verify Password

```java
boolean valid = BcryptEngine.verify("password", hash, config);
```

---

## 🔐 Security Features

* Constant-time hash comparison
* Secure salt generation (via `SecureRandom`)
* Optional pre-KDF: Argon2 or HKDF
* Strict FIPS mode: disables Blowfish if no KDF
* Immutable configs via builder
* Fully thread-safe implementation

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

---

### ⚠️ Password Length Limitation

Bcrypt limits passwords to 72 bytes. Any characters beyond that are ignored.  
To avoid unexpected behavior, it's recommended to pre-process passwords using a KDF such as Argon2 or HKDF,  
or hash the password with SHA-256 before passing it into Bcrypt.

---

## 🛠️ TODO / Improvements

- [ ] **Long password handling**: Add explicit validation or truncation notice for passwords longer than 72 bytes (Bcrypt ignores extra bytes).
- [ ] **HKDF input validation**: Ensure `HkdfEngine.derive()` throws clear exceptions when salt is null or too short, and when length is non-positive.
- [ ] **Bcrypt version selector**: Add support for selecting between `$2b$`, `$2a$`, or `$2y$` hashes for better interoperability.
- [ ] **Edge case unit tests**:
  - Test hashing with passwords longer than 72 bytes.
  - Test HKDF derivation with null or short salt.

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
