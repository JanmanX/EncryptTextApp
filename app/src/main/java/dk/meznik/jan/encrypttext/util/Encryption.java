package dk.meznik.jan.encrypttext.util;

import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
    private static final String TAG = "ENCRYPTION";

    private static final String AES_MODE = "AES/CBC/PKCS7Padding";
    private static final String ENCODING = "UTF-8";

    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String SALT = "d68a1c8a0a8b8710f7c771065165867fc8e73b50ee6809a7e9f53873b38e3e0d";

    private static SecretKeySpec generateKey(final String password) throws NoSuchAlgorithmException,
            UnsupportedEncodingException {

        // Create a SHA-256 hash of the password
        final MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);

        // Salt the password and get bytes using ENCODING.
        // It should not be necessary to salt with AES, but I do it nonetheless
        byte[] bytes = (password + SALT).getBytes(ENCODING);
        digest.update(bytes, 0, bytes.length);

        // Get the HASH
        byte[] key = digest.digest();

        // Using SHA-256, this returns a 256bit key
        return new SecretKeySpec(key, "AES");
    }


    public static String encrypt(final String password, String message) throws GeneralSecurityException {
        try {
            final SecretKeySpec key = generateKey(password);

            String iv = getRandomIV();
            Cipher cipher = Cipher.getInstance(AES_MODE);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] cipherText = cipher.doFinal(message.getBytes(ENCODING));

            return iv + Base64.encodeToString(cipherText, Base64.NO_WRAP);

        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }

    public static String decrypt(final String password, String base64CipherWithIV)
            throws GeneralSecurityException {

        try {
            final SecretKeySpec key = generateKey(password);
            String iv = base64CipherWithIV.substring(0, 16);
            String base64EncodedCipherText = base64CipherWithIV.substring(16);

            byte[] decodedCipherText = Base64.decode(base64EncodedCipherText, Base64.NO_WRAP);

            Cipher cipher = Cipher.getInstance(AES_MODE);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

            byte[] decryptedBytes = cipher.doFinal(decodedCipherText);
            return new String(decryptedBytes, ENCODING);

        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private static String getRandomIV() {
        // Using constant IV is vulnerable to some attacks. On the other hand, IV can be public.
        // Therefore, we generate a random IV and store it at the beginning of the ciphered text.

        Random random = new Random();
        StringBuilder builder = new StringBuilder();

        for (int i = 0; i < 16; ++i) {
            builder.append((char) (random.nextInt(96) + 32));
        }

        return builder.toString();
    }

}
