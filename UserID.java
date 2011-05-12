
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import javax.security.*;
import javax.security.auth.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class UserID {
	
	public static final String MAC_STANDARD = "HmacSHA256";
	public static final int MAC_LENGTH = 256;
	
	public final String uname;
	private char[] pass;
	private byte[] rsaPublic;
	private byte[] rsaPrivate;
	
	public static UserID login(String uname, char[] pass){
		try{
			SecureLayer tempLayer = new SecureLayer();
			tempLayer.selfInitRSA();
			return new UserID(uname, pass, tempLayer.descMyPublic(), tempLayer.descMyPrivate());
		}
		catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	private UserID load(String uname, char[] pass){
		return null;
	}
	
	private static Mac grabMac(String passString) throws NoSuchAlgorithmException, InvalidKeyException{
		Mac hmac = Mac.getInstance(MAC_STANDARD);
		SecretKeySpec secret = new SecretKeySpec(SecureLayer.stob(passString), MAC_STANDARD);
		hmac.init(secret);
		return hmac;
	}
	
	private static Cipher grabPBECipher(char[] password, boolean encrypt) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
		PBEKeySpec pbeKeySpec;
		PBEParameterSpec pbeParamSpec;
		SecretKeyFactory keyFac;

		// Salt
		byte[] salt = {
				(byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
				(byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
		};

		// Iteration count
		int count = 20;

		// Create PBE parameter set
		pbeParamSpec = new PBEParameterSpec(salt, count);
		pbeKeySpec = new PBEKeySpec(password);
		keyFac = SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");
		SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
		
		// Create PBE Cipher
		Cipher pbeCipher = Cipher.getInstance("PBEWithSHA1AndDESede");
		if(encrypt){
			pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
		}
		else{
			pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
		}
		return pbeCipher;
	}
	
	private boolean saveSelf(){
		try{
			Mac ma = grabMac(pass());
			Cipher ci = grabPBECipher(pass, true);
			File saveFile = new File(uname + ".pass");
			if(saveFile.exists()) ;//return false; //TODO remove comment
			saveFile.createNewFile();
			byte[] publen = pad(rsaPublic.length, 20);
			byte[] prilen = pad(rsaPrivate.length, 20);
			ma.update(publen);
			ma.update(rsaPublic);
			ma.update(prilen);
			byte[] hash = ma.doFinal(rsaPrivate);
			System.out.println(HashStalk.hexify(hash));
			FileOutputStream fos = new FileOutputStream(saveFile);
			fos.write(publen);
			fos.write(rsaPublic);
			fos.write(prilen);
			fos.write(rsaPrivate);
			fos.write(hash);
			//byte[] some = 
			//System.out.println(tot.length + " - " + HashStalk.hexify(tot));
			return true;
		}
		catch(Exception e){
			return false;
		}
	}
	
	private UserID(String un, char[] pa, byte[] pub, byte[] pri){
		uname = un;
		pass = new char[pa.length];
		System.arraycopy(pa, 0, pass, 0, pa.length);
		rsaPublic = SecureLayer.byteClone(pub);
		rsaPrivate = SecureLayer.byteClone(pri);
		
		System.out.println("lname: " + uname + "\npass: " + pass());
		System.out.println(SecureLayer.btos(rsaPublic));
		saveSelf();
	}

	public String pass(){
		return new String(pass);
	}
	
	public byte[] getPub(){
		return SecureLayer.byteClone(rsaPublic);
	}
	
	public byte[] getPri(){
		return SecureLayer.byteClone(rsaPrivate);
	}
	
	public static byte[] pad(int val, int len){
		byte[] shrt = SecureLayer.stob(val + ".");
		byte[] tot = new byte[len];
		for(int i=0; i<len; i++){
			if(i < shrt.length) tot[i] = shrt[i];
			else tot[i] = 0;
		}
		return tot;
	}
	
}
