// https://www.baeldung.com/java-read-pem-file-keys
// https://www.baeldung.com/java-rsa
// https://opensource.com/article/21/4/encryption-decryption-openssl
// https://www.devglan.com/online-tools/rsa-encryption-decryption
// https://www.java67.com/2016/09/Java-base64-encoding-and-decoding-example-in-JDK8.html

import java.util.Base64;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;

public class test {

private static final String PRIVATE_KEY = System.getenv("PRIVATE_KEY")
						.replace("-----BEGIN RSA PRIVATE KEY-----","")
						.replace("-----END RSA PRIVATE KEY-----","");

private static final String PUBLIC_KEY = System.getenv("PUBLIC_KEY")
						.replace("-----BEGIN PUBLIC KEY-----","")
						.replace("-----END PUBLIC KEY-----","");

private static final String secretMessage = "Baeldung secret message";
private static File encryptFile = new File("toto.enc");

// Then decrypt encrypted file "toto.enc" with private.key :
// openssl rsautl -decrypt -inkey key.pem -in toto.enc
// ou
// openssl base64 -d < toto.b64 > toto.decoded && openssl rsautl -decrypt -inkey key.pem -in toto.decoded
// result: Baeldung secret message

  public static void main(String[] args)  throws Exception {

    //System.out.println( PRIVATE_KEY );
    RSAPublicKey publicKey = readPublicKey();

    Cipher encryptCipher = Cipher.getInstance("RSA");
    encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

    byte[] secretMessageBytes = secretMessage.getBytes(StandardCharsets.UTF_8);
    byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);

    String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);

    //System.out.println( encryptedMessageBytes );
    System.out.println( encodedMessage );

    try (FileOutputStream stream = new FileOutputStream(encryptFile)) {
        stream.write(encryptedMessageBytes);
 	stream.flush();
	stream.close();
    } catch (Exception e) {
        e.printStackTrace();
    }



  }

public static RSAPublicKey readPublicKey() throws Exception {
    //String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

    String publicKeyPEM = PUBLIC_KEY
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replaceAll(System.lineSeparator(), "")
      .replace("-----END PUBLIC KEY-----", "");

    byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

    //System.out.println( encoded.toString() );

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    return (RSAPublicKey) keyFactory.generatePublic(keySpec);
}

}