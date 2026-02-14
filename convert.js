const crypto = require("crypto");

const PUBLIC_KEY_BASE64 =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdXh2VbzkwRMDTwn7zM9NfOhTfmYREP5Pf5/Kj14bfhstRBF5Fz3YR97bPyGRxfzGIpEXybCQxm0USC3Ib8HIjDZM3VrW//c2P0R8EJaM9XxuOfXRnyi+ADKlSQQZ4md3PcLAToPwTQ2U9RabDjT/O3gdQp6ocaIAyXcgj8pmCuQIDAQAB";

/**
 * Creates the encrypted payload (hash) of rawPassword using the public key.
 * Mirrors the Java flow: AES encrypts password string, RSA encrypts the AES key.
 *
 * @param {string} referenceId
 * @param {string} rawPassword
 * @param {string} [publicKeyBase64] - optional; defaults to PUBLIC_KEY_BASE64
 * @returns {string} Base64(encryptedPassword) + "||" + Base64(encryptedKey)
 */
function encryptPasswordWithPublicKey(referenceId, rawPassword, publicKeyBase64 = PUBLIC_KEY_BASE64) {
  const password = rawPassword + ":" + referenceId;
  const keySizeBytes = 32; // 256 bits for AES-256
  const algorithm = "aes-256-ecb";

  // 1. Generate random AES-256 key
  const symmetricKey = crypto.randomBytes(keySizeBytes);

  // 2. Encrypt password with AES/ECB/PKCS5Padding
  const cipher = crypto.createCipheriv(algorithm, symmetricKey, Buffer.alloc(0));
  const encryptedPassword = Buffer.concat([
    cipher.update(password, "utf8"),
    cipher.final(),
  ]);

  // 3. Encrypt symmetric key with RSA public key (PKCS1)
  const publicKeyDer = Buffer.from(publicKeyBase64, "base64");
  const publicKey = crypto.createPublicKey({
    key: publicKeyDer,
    format: "der",
    type: "spki",
  });
  const encryptedKey = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    symmetricKey
  );

  const passwordB64 = encryptedPassword.toString("base64");
  const keyB64 = encryptedKey.toString("base64");
  const response = passwordB64 + "||" + keyB64;

  return response;
}

// Run with same inputs as Java (referenceId, rawPassword)
const referenceId = "AINEXT";
const rawPassword = "ainext123";

console.log("*****Start****************");
console.log("referenceId:", referenceId);
console.log("rawPassword:", rawPassword);

const hash = encryptPasswordWithPublicKey(referenceId, rawPassword);

console.log("hash (password||authKey):", hash);
console.log("*****end****************");
