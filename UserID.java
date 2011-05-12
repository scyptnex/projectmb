
public class UserID {
	
	public final String uname;
	private char[] pass;
	private byte[] rsaPublic;
	private byte[] rsaPrivate;
	
	public static UserID login(String uname, char[] pass){
		return new UserID(uname, pass, new byte[0], new byte[0]);
	}
	
	public UserID(String un, char[] pa, byte[] pub, byte[] pri){
		uname = un;
		pass = new char[pa.length];
		System.arraycopy(pa, 0, pass, 0, pa.length);
		rsaPublic = SecureLayer.byteClone(pub);
		rsaPrivate = SecureLayer.byteClone(pri);
	}

	public String pass(){
		return new String(pass);
	}
	
}
