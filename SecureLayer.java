import java.nio.charset.Charset;
import java.security.interfaces.*;
import java.security.spec.*;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.*;

public class SecureLayer {
	
	public static final String MAC_STANDARD = "HmacSHA256";
	public static final String AES_STANDARD = "AES/CBC/PKCS5Padding";
	public static final int AES_LENGTH = 128; // 192 and 256 bits may not be available
	public static final int RSA_LENGTH = 2048;
	public static final int MAC_LENGTH = 256;
	
	public static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	
	//some nice randomness
	private SecureRandom rand;
	
	//rsa bits
	private RSAPublicKey yourPublic;
	private RSAPublicKey myPublic;
	private RSAPrivateKey myPrivate;
	private Cipher outCipher;
	private Cipher inCipher;
	
	//aes bits
	private byte[] rawKey;
	private byte[] initVec;
	private SecretKeySpec aesSpec;
	Cipher enc;
	Cipher dec;
	
	//all macs use hmacSHA256
	private Mac rsaMac;
	private Mac aesMac;
	private byte[] rsaMacRaw;
	private byte[] aesMacRaw;
	
	public static void main(String[] args) throws Exception{
		SecureLayer sl = new SecureLayer();
		sl.selfInitAES();
		sl.selfInitMac(true);
		System.out.println(btos(sl.aesMacRaw));
		
		String message = "This was a triumph.  I'm making a note here: 'HUGE SUCCESS!'.  It's hard to overstate my satisfaction";
		byte[] mb = stob(message);
		byte[] eb = sl.getAESEncrypted(mb);
		byte[] db = sl.getAESDecrypted(eb);
		System.out.println(btos(mb));
		System.out.println(btos(eb));
		System.out.println(btos(db));
	}
	
	public SecureLayer(){
		rand = new SecureRandom(new SecureRandom().generateSeed(32));
		
		yourPublic = null;
		myPublic = null;
		myPrivate = null;
		outCipher = null;
		inCipher = null;
		
		rawKey = null;
		aesSpec = null;
		enc = null;
		dec = null;
		
		rsaMac = null;
		aesMac = null;
		rsaMacRaw = null;
		aesMacRaw = null;
	}
	
	/*
	 * Self init methods
	 * These rely on a good and random secure random, its as random as it'll ever be after initialisation
	 */
	public void selfInitAES() throws SecurityException{
		try{
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(AES_LENGTH, rand);
			byte[] niv = new byte[AES_LENGTH/8];
			rand.nextBytes(niv);
			initAES(kgen.generateKey().getEncoded(), niv);
		}
		catch(NoSuchAlgorithmException exc){
			throw new SecurityException("AES Init: No Such Algorithm");
		}
	}
	
	public void selfInitMac(boolean useAES) throws SecurityException{
		byte[] nmac = new byte[MAC_LENGTH/8];
		rand.nextBytes(nmac);
		initMac(nmac, useAES);
	}
	
	
	/*
	 * Initialisers, adds to the security layer as parts become available
	 * The security layer starts non functional, each init gives it a new ability
	 */
	
	public void initAES(byte[] key, byte[] iv) throws SecurityException{
		try{
			rawKey = byteClone(key);
			
			initVec = byteClone(iv);
			AlgorithmParameterSpec ivs = new IvParameterSpec(initVec);
			
			aesSpec = new SecretKeySpec(rawKey, "AES");

			enc = Cipher.getInstance(AES_STANDARD);
			dec = Cipher.getInstance(AES_STANDARD);
			
			enc.init(Cipher.ENCRYPT_MODE, aesSpec, ivs);
			enc.init(Cipher.DECRYPT_MODE, aesSpec, ivs);
		}
		catch(NoSuchPaddingException exc){
			throw new SecurityException("AES Init: No Such Padding");
		}
		catch(NoSuchAlgorithmException exc){
			throw new SecurityException("AES Init: No Such Algorithm");
		}
		catch(InvalidAlgorithmParameterException exc){
			throw new SecurityException("AES Init: Invalid Algorithm Parameter");
		}
		catch(InvalidKeyException exc){
			throw new SecurityException("AES Init: Invalid Key");
		}
	}
	
	public void initMac(byte[] pass, boolean useAES) throws SecurityException{
		try{
			Mac hmac = Mac.getInstance(MAC_STANDARD);
			SecretKeySpec secret = new SecretKeySpec(pass, MAC_STANDARD);
			hmac.init(secret);
			if(useAES){
				if(aesMac != null) System.err.println("Warning: overwriting AES MAC");
				aesMac = hmac;
				aesMacRaw = byteClone(pass);
			}
			else{
				if(rsaMac != null) System.err.println("Warning: overwriting RSA MAC");
				rsaMac = hmac;
				rsaMacRaw = byteClone(pass);
			}
		}
		catch(Exception e){
			throw new SecurityException("Initializing the mac failed");
		}
	}
	
	
	/*
	 * Getters
	 * These perform an actual security function
	 * if the function hasnt been initialised, a SecurityException will be thrown
	 */
	
	//Note, this one does NOT automatically append the secure digest
	public byte[] getAESEncrypted(byte[] message) throws SecurityException{
		if(enc == null) throw new SecurityException("Unable to encrypt before AES key has been initialized");
		try{
			System.out.println(enc.getBlockSize());
			wtf i get an illegal block size here
			return enc.doFinal(message);
		}
		catch(BadPaddingException exc){
			throw new SecurityException("AES Encrypt: Bad Padding");
		}
		catch(IllegalBlockSizeException exc){
			throw new SecurityException("AES Encrypt: Illegal Block Size");
		}
	}
	
	public byte[] getAESDecrypted(byte[] message) throws SecurityException{
		if(dec == null) throw new SecurityException("Unable to decrypt before AES key has been initialized");
		try{
			return dec.doFinal(message);
		}
		catch(BadPaddingException exc){
			throw new SecurityException("AES Decrypt: Bad Padding");
		}
		catch(IllegalBlockSizeException exc){
			throw new SecurityException("AES Decrypt: Illegal Block Size");
		}
	}
	
	public byte[] getMac(byte[] message, boolean useAES) throws SecurityException{
		Mac thisMac = useAES ? aesMac : rsaMac;
		if(thisMac == null) throw new SecurityException("Unable to generate MAC before the MAC password has been initialized");
		return thisMac.doFinal(message);
	}
	
	/**
	 * Security exception
	 * literally just so i have an exception of my own to catch
	 * Raised with warnings when something bad happens, like verification failure, decryption failure, mac failure etc
	 */
	public static class SecurityException extends IOException{
		public SecurityException(String message){
			super(message);
		}
	}
	
	/**
	 * Static methods
	 */
	
	public static byte[] byteJoin(byte[] a, byte[] b){
		byte[] ret = new byte[a.length + b.length];
		for(int i=0; i<a.length; i++) ret[i] = a[i];
		for(int i=0; i<b.length; i++) ret[i+a.length] = b[i];
		return ret;
	}
	
	public static byte[] stob(String s){
		return s.getBytes(UTF8_CHARSET);
	}
	
	public static String btos(byte[] b){
		return new String(b, UTF8_CHARSET);
	}
	
	public static byte[] byteClone(byte[] a){
		byte[] ret = new byte[a.length];
		for(int i=0; i<a.length; i++) ret[i] = a[i];
		return ret;
	}
	
}