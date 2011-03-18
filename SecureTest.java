import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.*;
import java.security.spec.*;
import java.security.*;
import java.math.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SecureTest {
	public static void main(String[] args) throws Exception {
		
		for(Provider p : Security.getProviders()){
			System.out.println(p.getName() + "\t" + p.getInfo());
		}
		System.out.println();
		
		ERROR
		Serious problem:
			According to chinese remainer theorem (strange name), rsa is vulnerable if the same public exponent is continually used
			i have been unable to force these libraries to generate a public exponent other than 65537 (maybe its due to my computer)
		We have to figure out how to stop it from doing this
		ERROR
		
		SecureRandom sra = new SecureRandom();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024, sra);
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		RSAPublicKey pks = (RSAPublicKey)(keyPair.getPublic());
		String px = pks.getPublicExponent().toString();
		String pm = pks.getModulus().toString();
		System.out.println("PUBLIC:\n" + px + "\n" + pm + "\n");

		RSAPrivateKey prk = (RSAPrivateKey)(keyPair.getPrivate());
		String rx = prk.getPrivateExponent().toString();
		String rm = prk.getModulus().toString();
		System.out.println("PRIVATE:\n" + rx + "\n" + rm + "\n");

		KeyFactory fac = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec npk = new RSAPublicKeySpec(new BigInteger(pm), new BigInteger(px));//fac.getKeySpec(pks, RSAPublicKeySpec.class);
		Key k = fac.generatePublic(npk);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, k);

		byte[] plainBytes = "This is a sekret message MUAHAHAHAHAHAH".getBytes();
		System.out.println(new String(plainBytes));
		byte[] cipherText = cipher.doFinal(plainBytes);
		System.out.println(new String(cipherText));
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

		byte[] decryptedBytes = cipher.doFinal(cipherText);
		System.out.println(new String(decryptedBytes));
	}
}