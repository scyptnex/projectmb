import javax.crypto.*;
import javax.crypto.spec.*;

public class FileLoader {
	
	public static final String PBE_ALGO = "PBEWithSHA1AndDESede";
	
	//salts
	//the first 2 bytes of the salt comprise values between 0-64 each
	//there are a total of 4096 salts to crack
	public static byte ALPHA_RANGE = 64;
	public static byte BETA_RANGE = 64;
	private static final byte[] DEFAULT_SALT = {
			(byte)0x00, (byte)0x00, (byte)0x21, (byte)0x8c,
			(byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
	};

	// Iteration count
	public static final int count = 20;
	
	/**
	 * Atts
	 */
	public final byte alpha;
	public final byte beta;
	public final byte[] mySalt;
	public final char[] pass;
	
	private PBEParameterSpec pbeParamSpec;
	private SecretKey pbeKey;
	
	private Cipher enc, dec;
	
	public static void main(String[] args) throws Exception{
		FileLoader fl = new FileLoader((byte)63, (byte)63, "rofl");
		byte[] bs = SecureLayer.stob("This was a triumph!");
		byte[] cipher = fl.enc(bs);
		System.out.println(SecureLayer.btos(bs));
		System.out.println(SecureLayer.btos(cipher));
		for(byte a=0; a<ALPHA_RANGE; a++){
			for(byte b=0; b<BETA_RANGE; b++){
				try{
					FileLoader fil = new FileLoader(a, b, "rofl");
					byte[] dec = fil.dec(cipher);
					System.out.println(a + " " + b + ": " + SecureLayer.btos(dec));
				}
				catch(Exception e){
					//System.out.println(e.getClass().toString());
				} 
			}
		}
		System.out.println(SecureLayer.btos(fl.dec(cipher)));
	}
	
	public FileLoader(byte al, byte be, String password) throws Exception{
		alpha = (byte)(al%ALPHA_RANGE);
		beta = (byte)(be%BETA_RANGE);
		mySalt = new byte[DEFAULT_SALT.length];
		for(int i=0; i<mySalt.length; i++) mySalt[i] = DEFAULT_SALT[i];
		mySalt[0] = al;
		mySalt[1] = be;
		pass = password.toCharArray();
		
		pbeParamSpec = new PBEParameterSpec(mySalt, count);
		PBEKeySpec pbeKeySpec = new PBEKeySpec(pass);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance(PBE_ALGO);
		pbeKey = keyFac.generateSecret(pbeKeySpec);

		// Create PBE Cipher
		enc = Cipher.getInstance(PBE_ALGO);
		enc.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

		dec = Cipher.getInstance(PBE_ALGO);
		dec.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
	}
	
	public byte[] enc(byte[] data) throws Exception{
		return enc.doFinal(data);
	}
	
	public byte[] dec(byte[] data) throws Exception{
		return dec.doFinal(data);
	}
	
	public static void bout(byte[] b){
		System.out.print("|m| = " + b.length);
		for(int i=0; i<b.length; i++){
			if(i%8 == 0) System.out.println();
			int v = (b[i] < 0 ? 256+b[i] : b[i]);
			System.out.print(Long.toHexString(v) + "\t");
		}
		System.out.println();
	}
	
}