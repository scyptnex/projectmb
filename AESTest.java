import java.security.interfaces.*;
import java.security.spec.*;
import java.security.*;
import java.math.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

public class AESTest {
	public static String asHex (byte buf[]) {
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10)
				strbuf.append("0");

			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}

		return strbuf.toString();
	}

	public static void main(String[] args) throws Exception {
		byte[] sharedSecret = "Dead Beef is yum".getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] hash = md.digest(sharedSecret);
		SecureRandom rand = new SecureRandom(hash);
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128); // 192 and 256 bits may not be available
		
		byte[] iv = new byte[16];
		rand.nextBytes(iv);
		AlgorithmParameterSpec ivs = new IvParameterSpec(iv);

		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();

		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivs);

		byte[] encrypted =
			cipher.doFinal((args.length == 0 ?
					"This is just an example" : args[0]).getBytes());
		System.out.println("encrypted string: " + asHex(encrypted));

		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivs);
		byte[] original =
			cipher.doFinal(encrypted);
		String originalString = new String(original);
		System.out.println("Original string: " +
				originalString + " " + asHex(original));
	}
}
