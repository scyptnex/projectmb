import java.security.interfaces.*;
import java.security.spec.*;
import java.security.*;
import java.math.*;
import javax.crypto.*;

public class SafeExchange {
	
	/**
	 * ALEX read:
	 * to ensure non-repudiation only the server ever sends any public key in the clear:
	 * ==Connect to server==
	 * 1) client connects to server
	 * 2) server sends public key in the clear to client
	 * 3) client encrypts their own public key with server's public key and sends it to server
	 * 4) server determine's client's public key and randomly generates the mac password to be used, sends mac password encrypted by client's public key
	 * 5) client determine's mac password, generates AES key and IV, sends all 3 to server encrypted by server's public key
	 * 6) server recieves AES key and IV, notes that client was able to decrypt the right mac password, server sends IV alone - SERVER IS WILLING TO START AES
	 * 7) client confirms server decrypted IV - CLIENT IS WILLING TO START AES
	 * 8) AES communcation continues
	 * 
	 * ==Connect to client==
	 * 1) i request the server to start a conversation with you
	 * 2) the server sends me your known public key over AES
	 * 3) i route my public key encrypted with yours
	 * 4) you decrypt my public key and route a random mac password encrypted with my public key
	 * 4) i decrypt the random mac, generate an AES key and an IV and route them with your mac encrypted by your public key
	 * 5) you decrypt the AES key and IV, ensure i correctly decrypted the mac password, you send the IV alone - YOU ARE WILLING TO START AES
	 * 6) i ensure you correctly decrypted the IV - I AM WILLING TO START AES
	 * 7) AES communication continues
	 * 
	 * I figured we need all 7 steps to prevent man in the middle attacks
	 * The man in the middle can't pretend to be the server to you, so if you establish a connection to the server you really must be you
	 * And only the real you will be able to decrypt messages from me using your public key.
	 * In other words so long as the server tells me your public key (and not you) then no-one can pretend to be you during our conversation
	 * In the handshake, both sides have to show they really hold their private key by decrypting something functionally random.
	 *    the starter shows it by decrypting the mac password
	 *    the reciever shows it by decrypting the IV
	 * ALL STEPS EXCEPT THE FIRST PUBLIC KEY EXCHANGE USE A DIGEST TO ENSURE WEAK INTEGRITY
	 * ALL AES STEPS USE THE PRE-ARRANGED MAC PASSWORD TO ENSURE STRONG INTEGRITY
	 */
	
	private boolean initiator;
	private boolean keySent, testSent, testPassed;
	
	private RSAPublicKey yourPublic;
	private RSAPublicKey myPublic;
	private RSAPrivateKey myPrivate;
	
	
	
	public SafeExchange(){
		initiator = false;
	}
	
	/**
	 * Conversation recipient sends their public key to the conversation starter
	 * During client-client conversation, the server performs this step on their behalf
	 */
	public byte[] doAlpha(){
		byte[] ret = new byte[0];
		return ret;
	}
	
	/**
	 * Starter gets recipient's public key in the clear and sends their public key encrypted with it
	 * recipient's ability to send anything encrypted does NOT validate who they are
	 * 
	 * You are corrrect to point out this stage might as well be in the clear, but it occurs always on client machines and we might as well get in the habit of being secretive now
	 */
	public byte[] doBeta(byte[] alpha){
		byte[] ret = new byte[0];
		return ret;
	}
	
	/**
	 * If recipient can decrypt the beta blob, they are who they say they are, but being able to send encrypted traffic does not prove it
	 * Recipient gets starter's public key and ensures they are who they say by generating a random mac password
	 * If starter can decrypt the right mac password, then starter IS who they say they are
	 */
	public byte[] doGamma(byte[] beta){
		byte[] ret = new byte[0];
		return ret;
	}
	
	/**
	 * If starter can decrypt the right mac password, then they are who they say they are AND RECIPIENT KNOWS IT
	 * started generates and AES key and an IV and sends them with the correctly decrypted mac to recipient
	 * if recipient can talk to me with aes, then recipient IS who they say they are 
	 */
	public byte[] doEpsilon(byte[] gamma){
		byte[] ret = new byte[0];
		return ret;
	}
	
	/**
	 * Ensure that starter decrypted the right mac password, if they did then they are who they say they are
	 * prove to starter that i am recipient by correctly decrypting the IV and sending this to starter
	 * AFTER THIS ROUND recipient is able to communicate in AES
	 */
	public byte[] doZeta(byte[] epsilon){
		byte[] ret = new byte[0];
		return ret;
	}
	
	/**
	 * Final RSA round, ensure the client correctly decrypted IV
	 * After this round starter is able to communicate in AES
	 */
	public void getZeta(byte[] zeta){
		
	}
	
	/**
	 * Encrypting AES
	 */
	public byte[] lockAES(byte[] message){
		byte[] ret = new byte[0];
		return ret;
	}
	
	/**
	 * Decrypting AES
	 */
	public byte[] unlockAES(byte[] message){
		byte[] ret = new byte[0];
		return ret;
	}
	
	/**
	 * Encrypting RSA
	 * All RSA is encrypted using YOUR PUBLIC KEY
	 */
	private byte[] lockRSA(byte[] message){
		byte[] ret = new byte[0];
		return ret;
	}
	
	/**
	 * Decrypting RSA
	 * All RSA is decrypted using MY PRIVATE KEY
	 */
	private byte[] unlocRSA(byte[] message){
		byte[] ret = new byte[0];
		return ret;
	}
}