
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
			UserID attempt = load(uname, pass);
			if(attempt != null) return attempt;
			SecureLayer tempLayer = new SecureLayer();
			tempLayer.selfInitRSA();
			return new UserID(uname, pass, tempLayer.descMyPublic(), tempLayer.descMyPrivate());
		}
		catch(Exception e){
			e.printStackTrace();
			System.err.println("There was some failure trying to login with username " + uname);
			return null;
		}
	}

	private static UserID load(String uname, char[] pass) throws Exception{
		File infi = new File(uname + ".pass");
		if(!infi.exists()) return null;//make a new user

		Mac ma = grabMac(new String(pass));
		Cipher ci = grabPBECipher(pass, false);

		InputStream fis = new CipherInputStream(new FileInputStream(infi), ci);

		byte[] totin = new byte[(int)infi.length()*2];
		int numRead = 0;
		int totRead = 0;
		while((numRead = fis.read(totin, totRead, totin.length - totRead) ) >= 0){
			totRead += numRead;
		}
		byte[] publen = new byte[20];
		byte[] prilen = new byte[20];
		System.arraycopy(totin, 0, publen, 0, 20);
		System.arraycopy(totin, 20, prilen, 0, 20);
		String pubString = SecureLayer.btos(publen);
		int pubSize = Integer.parseInt(pubString.substring(0, pubString.indexOf(".")));
		String priString = SecureLayer.btos(prilen);
		int priSize = Integer.parseInt(priString.substring(0, priString.indexOf(".")));

		byte[] pubDesc = new byte[pubSize];
		byte[] priDesc = new byte[priSize];
		byte[] hash = new byte[MAC_LENGTH/8];
		System.arraycopy(totin, 40, pubDesc, 0, pubSize);
		System.arraycopy(totin, 40+pubSize, priDesc, 0, priSize);
		System.arraycopy(totin, 40+pubSize+priSize, hash, 0, hash.length);

		ma.update(publen);
		ma.update(prilen);
		ma.update(pubDesc);
		byte[] expectedHash = ma.doFinal(priDesc);

		System.out.println(HashStalk.hexify(publen) + "\n" + HashStalk.hexify(prilen) + "\n" + HashStalk.hexify(pubDesc) + "\n" + HashStalk.hexify(priDesc) + "\n" + HashStalk.hexify(hash));

		for(int i=0; i<hash.length; i++){
			if(hash[i] != expectedHash[i]){
				System.err.println("Hash doesnt match:");
				System.err.println(HashStalk.hexify(hash));
				System.err.println(HashStalk.hexify(expectedHash));
				System.err.println("Suspected trickery");
				throw new Exception("Suspected shenanigans");
			}
		}
		return new UserID(uname, pass, pubDesc, priDesc);
	}

	private boolean saveSelf(){
		try{
			File saveFile = new File(uname + ".pass");
			if(saveFile.exists()) return false; //TODO remove comment
			saveFile.createNewFile();

			Mac ma = grabMac(pass());
			Cipher ci = grabPBECipher(pass, true);

			byte[] publen = pad(rsaPublic.length, 20);
			byte[] prilen = pad(rsaPrivate.length, 20);
			ma.update(publen);
			ma.update(prilen);
			ma.update(rsaPublic);
			byte[] hash = ma.doFinal(rsaPrivate);
			OutputStream fos = new CipherOutputStream(new FileOutputStream(saveFile), ci);
			fos.write(publen);//ci.update(publen));
			fos.write(prilen);//ci.update(prilen));
			fos.write(rsaPublic);//ci.update(rsaPublic));
			fos.write(rsaPrivate);//ci.update(rsaPrivate));
			fos.write(hash);//ci.doFinal(hash));
			fos.close();
			System.out.println(rsaPublic.length + rsaPrivate.length + 40 + (MAC_LENGTH/8));
			System.out.println(HashStalk.hexify(publen) + "\n" + HashStalk.hexify(prilen) + "\n" + HashStalk.hexify(rsaPublic) + "\n" + HashStalk.hexify(rsaPrivate) + "\n" + HashStalk.hexify(hash));
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
		if(!saveSelf()){
			System.out.println("User already exists, we wont overwrite the file");
		}
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

}
