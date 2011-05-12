import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashStalk {
	private int size;
	private byte[] bottom;
	public static final int HASH_NUM_BYTES = 32;
	

	public static void main(String[] args)
	{
		System.out.println(hexify(getHash("kjhgkjhgkjhg".getBytes(), 5)));
		
		HashStalk hs = new HashStalk(2);
		System.out.println(hexify(hs.getTop()));
	}

	public HashStalk(int n) {
		size = n;
		bottom = new byte[HASH_NUM_BYTES];
		SecureRandom rand = new SecureRandom(new SecureRandom().generateSeed(32));
		rand.nextBytes(bottom);
	}
	
	public byte[] getTop()
	{
		return getHash(bottom, size);
	}
	
	public byte[] getCoin(int n)
	{
		if (size - n >= 0)
		{
			size -= n;
			return getHash(bottom, size);
		} else {
			return null;
		}
	}
	
	public int getSize()
	{
		return size;
	}
	
	//public static boolean check(byte[] c, int n, byte[] t)
	//{
	//	return (getHash(c, n) == t);
	//}
	
	public static byte[] getHash(byte[] h, int n)
	{
		MessageDigest sha = null;
		
		try {
			sha = MessageDigest.getInstance("SHA-256");
			sha.reset();
		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}
		
		for (;n != 0; n--)
		{
			h = sha.digest(h);
		}
		return h;
	}
	
	public static String hexify(byte[] b){
		if(b.length > 2000) System.err.println("Sending size " + b.length + " is doomed to fail");
		StringBuffer ret = new StringBuffer();//because many small additions are required
		for(int i=0; i<b.length; i++){
			int v = (b[i] < 0 ? 256+b[i] : b[i]);
			String tmp = Long.toHexString(v);
			ret.append(tmp.length() > 1 ? tmp: "0" + tmp);
		}
		return ret.toString();
	}

	public static byte[] dehexify(String m){
		byte[] ret = new byte[m.length()/2];
		for(int i=0; i<ret.length; i++){
			ret[i] = (byte)Long.parseLong(m.substring(i*2, i*2+2), 16);
		}
		return ret;
	}
}
