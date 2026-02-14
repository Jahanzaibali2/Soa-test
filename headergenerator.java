import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {


        encryptTest("654647644","GNB123","MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdXh2VbzkwRMDTwn7zM9NfOhTfmYREP5Pf5/Kj14bfhstRBF5Fz3YR97bPyGRxfzGIpEXybCQxm0USC3Ib8HIjDZM3VrW//c2P0R8EJaM9XxuOfXRnyi+ADKlSQQZ4md3PcLAToPwTQ2U9RabDjT/O3gdQp6ocaIAyXcgj8pmCuQIDAQAB","GNB123");

    }

    public static String encryptTest(String referenceId, String rawPassword, String publicKey, String newPassword) throws NoSuchAlgorithmException {
        publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdXh2VbzkwRMDTwn7zM9NfOhTfmYREP5Pf5/Kj14bfhstRBF5Fz3YR97bPyGRxfzGIpEXybCQxm0USC3Ib8HIjDZM3VrW//c2P0R8EJaM9XxuOfXRnyi+ADKlSQQZ4md3PcLAToPwTQ2U9RabDjT/O3gdQp6ocaIAyXcgj8pmCuQIDAQAB";

        long keySize = 256;
        String algorithm = "AES";
        rawPassword = "ainext123";
        System.out.println("*****Start****************");
        System.out.println("referenceId: " + referenceId);
        String password = rawPassword + ":" + referenceId;

// # generate hash of the raw password using public key
        
        byte[] key = generateSymmetricKey(keySize, algorithm);

        byte[] encryptedPassword = encrypt(password.getBytes(), "AES/ECB/PKCS5Padding", key, null);

        System.out.println("password: " + Base64.getEncoder().encodeToString(encryptedPassword));

        byte[] encryptedKey = encryptAsymmetric(key, "RSA/ECB/PKCS1Padding", Base64.getDecoder().decode(publicKey));
        System.out.println("authKey: " + Base64.getEncoder().encodeToString(encryptedKey));
        System.out.println("*****end****************");
        String response = Base64.getEncoder().encodeToString(encryptedPassword) + "||" + Base64.getEncoder().encodeToString(encryptedKey);

        return response;

    }

    public static byte[] encryptAsymmetric(byte[] data, String algorithm, byte[] key) {
        byte[] encryptedBytes = null;

        try {
            String[] algo = algorithm.split("/");
            KeyFactory kf = KeyFactory.getInstance(algo[0]);
            PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(key));

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            encryptedBytes = cipher.doFinal(data);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return encryptedBytes;
    }

    public static byte[] encrypt(byte[] data, String algorithm, byte[] key, byte[] iv) {
        byte[] encryptedBytes = null;

        try {
            String[] algo = algorithm.split("/");
            SecretKeySpec secretKey = new SecretKeySpec(key, algo[0]);
            Cipher cipher = Cipher.getInstance(algorithm);

            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }

            encryptedBytes = cipher.doFinal(data);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return encryptedBytes;
    }

    public static byte[] generateSymmetricKey(long keySize, String algorithm) throws NoSuchAlgorithmException {
        int keySizeInt=(int)keySize;
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance(algorithm);
        keygenerator.init(keySizeInt, securerandom);
        SecretKey key = keygenerator.generateKey();
        return key.getEncoded();
    }
}