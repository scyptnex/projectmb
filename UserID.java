
public class UserID {
	
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
	
	public UserID(String un, char[] pa, byte[] pub, byte[] pri){
		uname = un;
		pass = new char[pa.length];
		System.arraycopy(pa, 0, pass, 0, pa.length);
		rsaPublic = SecureLayer.byteClone(pub);
		rsaPrivate = SecureLayer.byteClone(pri);
		
		System.out.println("lname: " + uname + "\npass: " + pass());
		System.out.println(HashStalk.hexify(rsaPublic));
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
	
}
