import java.security.interfaces.*;
import java.security.spec.*;
import java.security.*;
import java.math.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.nio.charset.Charset;

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
		
		byte[] tmp = new byte[256];
		for(int i=0; i<256; i++){
			tmp[i] = (byte)i;
		}
		String hex = StealthNetComms.hexEncode(tmp);
		System.out.println(hex);
		byte[] rvt = StealthNetComms.hexDecode(hex);
		for(int i=0; i<256; i++){
			if(rvt[i] != tmp[i]) System.out.println("FAIL: " + rvt[i] + tmp[i]);
		}
		if(rvt.length != tmp.length) System.out.println("LENGTH FAIL");
		
		byte[] sharedSecret = "Dead Beef is yum".getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] hash = md.digest(sharedSecret);
		System.out.println(hash.length);
		SecureRandom rand = new SecureRandom(hash);
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128); // 192 and 256 bits may not be available
		
		Mac hmacSha256 = Mac.getInstance("hmacSHA256");
		SecretKeySpec secret = new SecretKeySpec("roflkey".getBytes(),"HmacSHA256");
		hmacSha256.init(secret);
		final Charset UTF8_CHARSET = Charset.forName("UTF-8");
		byte[] mess = "You can do what you will, but step way over my blue sued shoes".getBytes(UTF8_CHARSET);
		byte[] hmac = hmacSha256.doFinal(mess);
		byte[] umac = md.digest(mess);
		System.out.println("Original: l=" + mess.length + "\t \"" + new String(mess, UTF8_CHARSET) + "\"");
		System.out.println("MAC:      l=" + hmac.length + "\t \"" + new String(hmac, UTF8_CHARSET) + "\"");
		System.out.println("MD:       l=" + umac.length + "\t \"" + new String(umac, UTF8_CHARSET) + "\"");
		
		byte[] iv = new byte[16];
		rand.nextBytes(iv);
		AlgorithmParameterSpec ivs = new IvParameterSpec(iv);

		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		
		System.out.println(raw.length + " - key: " + asHex(raw));

		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivs);
		
		byte[] mb = "This was a triumph.  I'm making a note here: 'HUGE SUCCESS!'.  It's hard to overstate my satisfaction".getBytes();
		
		System.out.println(mb.length);
		
		byte[] encrypted = cipher.doFinal(mb);
		System.out.println("encrypted string: " + asHex(encrypted));
		
		encrypted = cipher.doFinal(mb);
		System.out.println("encrypted string(" + encrypted.length + "): " + asHex(encrypted));

		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivs);
		byte[] original =
			cipher.doFinal(encrypted);
		String originalString = new String(original);
		System.out.println("Original string: " +
				originalString + " " + asHex(original));
	}
}
