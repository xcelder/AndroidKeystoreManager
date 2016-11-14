package gc.com.keystoremanager;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

/**
 * Created by xcelder1 on 11/7/16.
 */
public class KeystoreManager {

    KeyStore keyStore;
    KeyPair keyPair;
    static final String ALIAS = "YOUR_ALIAS"; //Enter your alias here (only a name for the key pair instance)
    static final String KEY_ALGORITHM_RSA = "RSA";
    static final String KEYSTORE_NAME = "AndroidKeyStore";
    private static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String ALGORITHM_M = "RSA/None/PKCS1Padding";
    private static final String PROVIDER = "AndroidOpenSSL";
    private static final String PROVIDER_M = "AndroidKeyStoreBCWorkaround";

    private static KeystoreManager instance;
    private final SharedPreferences sharedPreferences;

    public static void init(Context context){
        try {
            instance = new KeystoreManager(context);
        } catch (KeystoreManagerException e) {
            e.printStackTrace();
        }
    }

    public static KeystoreManager getInstance(){
        return instance;
    }

    public String getPreference(String key){
        try {
            key = encryptText(key);

        String value = this.sharedPreferences.getString(key, "");
        if("".equals(value)) return value;
        else return decryptText(value);
        } catch (KeystoreManagerException e) {
            return "";
        }
    }

    public void setPreference(String key, String value){
        try {
            value = encryptText(value);
            key = encryptText(key);
            this.sharedPreferences.edit().putString(key, value).commit();
        } catch (KeystoreManagerException e) {
            e.printStackTrace();
        }
    }

    public void removePreferences(){
        this.sharedPreferences.edit().clear().commit();
    }

    public KeystoreManager(Context context) throws KeystoreManagerException {

        sharedPreferences = context.getSharedPreferences("KeyStore", 0);

        try {
            keyStore = KeyStore.getInstance(KEYSTORE_NAME);
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new KeystoreManagerException(e.getMessage());
        }
        try {
            // Create new key if needed
            if (!keyStore.containsAlias(ALIAS)) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM_RSA, KEYSTORE_NAME);
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                            ALIAS,
                            KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                            .build();
                    generator.initialize(spec);
                } else {
                    Calendar start = Calendar.getInstance();
                    Calendar end = Calendar.getInstance();
                    end.add(Calendar.YEAR, 1);
                    KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                            .setAlias(ALIAS)
                            .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                            .setSerialNumber(BigInteger.ONE)
                            .setStartDate(start.getTime())
                            .setEndDate(end.getTime())
                            .build();
                    generator.initialize(spec);
                }

                keyPair = generator.generateKeyPair();

            }

        } catch (Exception e) {
            throw new KeystoreManagerException(e.getMessage());
        }
    }

    /**
     * Method for encrypt a text with your own Android KeyStore
     *
     * @param txt The text you want to encrypt
     * @return String with your text finally encrypted
     * @throws KeystoreManagerException
     */
    public String encryptText(String txt) throws KeystoreManagerException {
        String encryptedText = "";
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, null);
            PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();

            // Encrypt the text
            if (txt.isEmpty()) {
                throw new KeystoreManagerException(KeystoreManagerException.EXCEPTION_EMPTY_TEXT);
            }
            Cipher input;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M)
                input = Cipher.getInstance(ALGORITHM_M, PROVIDER_M);
            else
                input = Cipher.getInstance(ALGORITHM, PROVIDER);

            input.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, input);
            cipherOutputStream.write(txt.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte[] vals = outputStream.toByteArray();

            encryptedText = Base64.encodeToString(vals, Base64.DEFAULT);
            return encryptedText;
        } catch (Exception e) {
            throw new KeystoreManagerException("Exception " + e.getMessage() + " occured");
        }


    }

    /**
     * Method for decrypt a text with your own Android KeyStore
     *
     * @param txt The text you want to decrypt
     * @return String with your text finally decrypted
     * @throws KeystoreManagerException
     */
    public String decryptText(String txt) throws KeystoreManagerException {
        String decryptedText = "";
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, null);
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            Cipher output;
            try {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M)
                    output = Cipher.getInstance(ALGORITHM_M, PROVIDER_M);
                else
                    output = Cipher.getInstance(ALGORITHM, PROVIDER);
                output.init(Cipher.DECRYPT_MODE, privateKey);
                CipherInputStream cipherInputStream = new CipherInputStream(
                        new ByteArrayInputStream(Base64.decode(txt, Base64.DEFAULT)), output);
                ArrayList<Byte> values = new ArrayList<>();
                int nextByte;
                while ((nextByte = cipherInputStream.read()) != -1) {
                    values.add((byte) nextByte);
                }
                byte[] bytes = new byte[values.size()];
                for (int i = 0; i < bytes.length; i++) {
                    bytes[i] = values.get(i);
                }

                decryptedText = new String(bytes, 0, bytes.length, "UTF-8");
                return decryptedText;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | NoSuchProviderException | InvalidKeyException e) {
                throw new KeystoreManagerException(e.getMessage());
            }
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new KeystoreManagerException(e.getMessage());
        }


    }

    /**
     * Method for encrypt a byte array with your own Android KeyStore
     *
     * @param bytes The byte array you want to encrypt
     * @return Byte array with your bytes finally encrypted
     * @throws KeystoreManagerException
     */
    public byte[] encryptBytes(byte[] bytes) throws KeystoreManagerException {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, null);
            PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();

            // Encrypt the text
            if (bytes.length <= 0) {
                throw new KeystoreManagerException(KeystoreManagerException.EXCEPTION_EMPTY_TEXT);
            }
            Cipher input;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M)
                input = Cipher.getInstance(ALGORITHM_M, PROVIDER_M);
            else
                input = Cipher.getInstance(ALGORITHM, PROVIDER);

            input.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, input);
            cipherOutputStream.write(bytes);
            cipherOutputStream.close();

            return outputStream.toByteArray();

        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException
                | UnrecoverableEntryException | NoSuchPaddingException
                | NoSuchProviderException | KeystoreManagerException | KeyStoreException e) {
            throw new KeystoreManagerException("Exception " + e.getMessage() + " occured");
        }
    }

    /**
     * Method for decrypt a byte array with your own Android KeyStore
     *
     * @param bytes The byte array you want to decrypt
     * @return Byte array with your bytes finally decrypted
     * @throws KeystoreManagerException
     */
    public byte[] decryptBytes(byte[] bytes) throws KeystoreManagerException {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, null);
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            Cipher output;
            try {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M)
                    output = Cipher.getInstance(ALGORITHM_M, PROVIDER_M);
                else
                    output = Cipher.getInstance(ALGORITHM, PROVIDER);
//}
                output.init(Cipher.DECRYPT_MODE, privateKey);
                CipherInputStream cipherInputStream = new CipherInputStream(
                        new ByteArrayInputStream(bytes), output);
                ArrayList<Byte> values = new ArrayList<>();
                int nextByte;
                while ((nextByte = cipherInputStream.read()) != -1) {
                    values.add((byte) nextByte);
                }
                byte[] result = new byte[values.size()];
                for (int i = 0; i < result.length; i++) {
                    result[i] = values.get(i);
                }

                return result;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | NoSuchProviderException | InvalidKeyException e) {
                throw new KeystoreManagerException(e.getMessage());
            }
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new KeystoreManagerException(e.getMessage());
        }
    }

    /**
     * @return Your KeyStore instance with the Alias you defined
     */
    public KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * @return A KeyPair with an asymmetric pair of public and private keys generated by the KeyStore instance that was decided with the Alias you have chosen
     * @throws KeystoreManagerException
     */
    public KeyPair getKeyPair() throws KeystoreManagerException {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, null);
            return new KeyPair(privateKeyEntry.getCertificate().getPublicKey(), privateKeyEntry.getPrivateKey());
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new KeystoreManagerException(e.getMessage());
        }
    }
}
