// https://www.javacodegeeks.com/2020/04/encrypt-with-openssl-decrypt-with-java-using-openssl-rsa-public-private-keys.html

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 *
 * @author Michael Remijan mjremijan@yahoo.com @mjremijan
 */
public class Rsa4096 {
 
  private KeyFactory keyFactory;
  private PrivateKey privateKey;
  private PublicKey publicKey;
 
  public Rsa4096(
      String privateKeyClassPathResource
    , String publicKeyClassPathResource
  ) throws Exception {
    setKeyFactory();
    setPrivateKey(privateKeyClassPathResource);
    setPublicKey(publicKeyClassPathResource);
  }
 
  protected void setKeyFactory() throws Exception {
    this.keyFactory = KeyFactory.getInstance("RSA");
  }
 
  protected void __setPrivateKey(String classpathResource)
  throws Exception {
    InputStream is = this
      .getClass()
      .getClassLoader()
      .getResourceAsStream(classpathResource);
 
    String stringBefore
      = new String(is.readAllBytes());
    is.close();

    System.out.printf("%s%n",stringBefore);
 
    String stringAfter = stringBefore
      .replaceAll("\\n", "").replaceAll("\\r", "")
      .replaceAll("-----BEGIN PRIVATE KEY-----", "")
      .replaceAll("-----END PRIVATE KEY-----", "")
      .trim();
 
    byte[] decoded = Base64
      .getDecoder()
      .decode(stringAfter);
 
    KeySpec keySpec
      = new PKCS8EncodedKeySpec(decoded);
 
    privateKey = keyFactory.generatePrivate(keySpec);
  }
 
  protected void __setPublicKey(String classpathResource)
  throws Exception {
 
    InputStream is = this
      .getClass()
      .getClassLoader()
      .getResourceAsStream(classpathResource);
 
    String stringBefore
      = new String(is.readAllBytes());
    is.close();
 
    String stringAfter = stringBefore
      .replaceAll("\\n", "").replaceAll("\\r", "")
      .replaceAll("-----BEGIN PUBLIC KEY-----", "")
      .replaceAll("-----END PUBLIC KEY-----", "")
      .trim()
    ;
 
    byte[] decoded = Base64
      .getDecoder()
      .decode(stringAfter);
 
    KeySpec keySpec
      = new X509EncodedKeySpec(decoded);
 
    publicKey = keyFactory.generatePublic(keySpec);
  }
 

  protected void setPrivateKey(String key)
  throws Exception {

        try (InputStream input = new FileInputStream("./config.properties")) {

            Properties prop = new Properties();

            // load a properties file
            prop.load(input);

            // get the property value and print it out
            String stringBefore = prop.getProperty(key);


    String stringAfter = stringBefore
      .replaceAll("\\n", "").replaceAll("\\r", "")
      .replaceAll("-----BEGIN PRIVATE KEY-----", "")
      .replaceAll("-----END PRIVATE KEY-----", "")
      .trim();
 
    byte[] decoded = Base64
      .getDecoder()
      .decode(stringAfter);
 
    KeySpec keySpec
      = new PKCS8EncodedKeySpec(decoded);
 
    privateKey = keyFactory.generatePrivate(keySpec);

        } catch (IOException ex) {
            ex.printStackTrace();
        }

  }

  protected void setPublicKey(String key)
  throws Exception {

        try (InputStream input = new FileInputStream("./config.properties")) {

            Properties prop = new Properties();

            // load a properties file
            prop.load(input);

            // get the property value and print it out
            String stringBefore = prop.getProperty(key);
 
    String stringAfter = stringBefore
      .replaceAll("\\n", "").replaceAll("\\r", "")
      .replaceAll("-----BEGIN PUBLIC KEY-----", "")
      .replaceAll("-----END PUBLIC KEY-----", "")
      .trim()
    ;
 
    byte[] decoded = Base64
      .getDecoder()
      .decode(stringAfter);
 
    KeySpec keySpec
      = new X509EncodedKeySpec(decoded);
 
    publicKey = keyFactory.generatePublic(keySpec);

        } catch (IOException ex) {
            ex.printStackTrace();
        }

  }
 
  public String encryptToBase64(String plainText) {
    String encoded = null;
    try {
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] encrypted = cipher.doFinal(plainText.getBytes());
      encoded = Base64.getEncoder().encodeToString(encrypted);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return encoded;
  }
 
  public String decryptFromBase64(String base64EncodedEncryptedBytes) {
    String plainText = null;
    try {
      final Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      byte[] decoded = Base64
        .getDecoder()
        .decode(base64EncodedEncryptedBytes);
      byte[] decrypted = cipher.doFinal(decoded);
      plainText = new String(decrypted);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
    return plainText;
  }


  public static void main(String[] args)
    throws Exception {

    test();

  }
 
  public static void test() throws Exception {
    // Setup
    Rsa4096 rsa = new Rsa4096(
        "private.key"
      , "public.key"
    );
    String expected
      = "Text to be encrypted";
 
    // Test
    String encryptedAndEncoded
      = rsa.encryptToBase64(expected);
    String actual
      = rsa.decryptFromBase64(encryptedAndEncoded);
 
    // Assert
    System.out.printf("%s - %s%n",expected, actual);
  }

}