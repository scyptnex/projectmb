/***********************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetComms.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Communications for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0
 * IMPLEMENTS:      initiateSession();
 *                  acceptSession();
 *                  terminateSession();
 *                  sendPacket();
 *                  recvPacket();
 *                  recvReady();
 *
 * REVISION HISTORY:
 *
 **********************************************************************************/

/* Import Libraries **********************************************************/

import java.net.*;
import java.io.*;

/* StealthNetComms class *****************************************************/

public class StealthNetComms {

	//CHEESE
	private static final char[] HEXTABLE = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	public static String getDefaultServerName(){
		return "localhost";
	}
	public static int getDefaultServerPort(){
		return 5616;
	}

	private Socket commsSocket;             // communications socket
	private PrintWriter dataOut;            // output data stream
	private BufferedReader dataIn;          // input data stream
	private SecureLayer secureLayer;
	private boolean secure;

	public StealthNetComms() {
		commsSocket = null;
		dataIn = null;
		dataOut = null;
		secureLayer = new SecureLayer();
		try {
			secureLayer.selfInitRSA();
		} catch (Exception e) {
			System.out.println("Problem initialising RSA.");
			//TODO Do something better here?
		}
		secure = false;
	}
	
	public StealthNetComms(SecureLayer sl) {
		commsSocket = null;
		dataIn = null;
		dataOut = null;
		secureLayer = sl;
		secure = false;
	}

	protected void finalize() throws IOException {
		if (dataOut != null)
			dataOut.close();
		if (dataIn != null)
			dataIn.close();
		if (commsSocket != null)
			commsSocket.close();
	}

	public boolean initiateSession(Socket socket) {
		try {
			System.out.println("Init Session");
			commsSocket = socket;
			dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
			dataIn = new BufferedReader(new InputStreamReader(
					commsSocket.getInputStream()));
			
			StealthNetPacket pckt = new StealthNetPacket();
			boolean done = false;
			while (!done) {
				pckt = recvPacket();
				switch (pckt.command) {
				case StealthNetPacket.CMD_PUBLICKEY:
					//System.out.println("init handshake recv");
					secureLayer.initRSAYou(pckt.data);
					
					sendPacket(StealthNetPacket.CMD_PUBLICKEY, secureLayer.descMyPublic());
					break;
					
				case StealthNetPacket.CMD_MAC:
					//System.out.println("MAC received");
					
					secureLayer.initMac(secureLayer.getRSADecrypted(pckt.data), true);
					secureLayer.selfInitAES();
					
					System.out.println(SecureLayer.btos(secureLayer.descAES()));
					System.out.println(SecureLayer.btos(secureLayer.descIV()));
										
					byte[] msg = SecureLayer.byteJoin(secureLayer.descAES(), secureLayer.descIV());
					msg = SecureLayer.byteJoin(msg, secureLayer.getRSADecrypted(pckt.data));
					
					sendPacket(StealthNetPacket.CMD_INITAES, secureLayer.getRSAEncrypted(msg));
					
					break;
					
				case StealthNetPacket.CMD_INITAES:
					//System.out.println(SecureLayer.btos(secureLayer.getRSADecrypted(pckt.data)));
					
					//TODO Check IV
					done = true;
					secure = true;
					break;
					
				default:
					done = true;
				}
			}
			
		} catch (Exception e) {
			System.err.println("Connection terminated.");
			System.exit(1);
		}

		return secure;
	}

	public boolean acceptSession(Socket socket) {
		try {
			System.out.println("Accept Session");
			commsSocket = socket;
			dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
			dataIn = new BufferedReader(new InputStreamReader(
					commsSocket.getInputStream()));
			
			if (secureLayer != null)
			{
				System.out.println(secureLayer.descMyPublic());
				sendPacket(StealthNetPacket.CMD_PUBLICKEY, secureLayer.descMyPublic());
			}
			
			StealthNetPacket pckt = new StealthNetPacket();
			boolean done = false;
			while (!done) {
				pckt = recvPacket();
				switch (pckt.command) {
				case StealthNetPacket.CMD_PUBLICKEY:
					//System.out.println("Public key received");
					secureLayer.initRSAYou(pckt.data);
					
					secureLayer.selfInitMac(true);
					
					//System.out.println(SecureLayer.btos(secureLayer.descMAC(true)));
					
					sendPacket(StealthNetPacket.CMD_MAC, secureLayer.getRSAEncrypted(secureLayer.descMAC(true)));
					
					break;
					
				case StealthNetPacket.CMD_INITAES:
					System.out.println("Initialising AES");
					byte[] key = new byte[16];
					byte[] iv = new byte[16];
					byte[] tmp = new byte[32];
					byte[] mac = new byte[32];
					
					SecureLayer.byteSplit(secureLayer.getRSADecrypted(pckt.data), tmp, mac);
					SecureLayer.byteSplit(tmp, key, iv);
					
					//System.out.println(SecureLayer.btos(mac));
					System.out.println(SecureLayer.btos(key));
					System.out.println(SecureLayer.btos(iv));
					
					//TODO mac check
					
					secureLayer.initAES(key, iv);
					
					sendPacket(StealthNetPacket.CMD_INITAES, secureLayer.getRSAEncrypted(iv));
					
					done = true;
					secure = true;
					
					break;
					
				default:
					done = true;
				}
			}
		} catch (Exception e) {
			System.err.println("Connection terminated.");
			System.exit(1);
		}
		return secure;
	}

	public boolean terminateSession() {
		try {
			System.out.println("Terminate Session");
			if (commsSocket == null)
				return false;
			dataIn.close();
			dataOut.close();
			commsSocket.close();
			commsSocket = null;
		} catch (Exception e) {
			return false;
		}

		return true;
	}

	public boolean sendPacket(byte command) {
		return sendPacket(command, new byte[0]);
	}

	public boolean sendPacket(byte command, String data) {
		return sendPacket(command, data.getBytes());
	}

	public boolean sendPacket(byte command, byte[] data) {
		return sendPacket(command, data, data.length);
	}

	public boolean sendPacket(byte command, byte[] data, int size) {
		StealthNetPacket pckt = new StealthNetPacket();
		pckt.command = command;
		pckt.data = new byte[size];
		System.arraycopy(data, 0, pckt.data, 0, size);
		return sendPacket(pckt);
	}

	public boolean sendPacket(StealthNetPacket pckt) {
		if (dataOut == null)
			return false;
		//System.out.println("SEND: " + new String(pckt.data) + " = " + pckt.toString());
		if (secure) {
			try {
			    byte[] data = secureLayer.getAESEncrypted(pckt.toBytes());
				dataOut.println(hexEncode(data));
			} catch (SecureLayer.SecurityException e) {
				System.out.println("Security failed on comms");
			}
		} else {
			dataOut.println(pckt.toString());
		}
		return true;
	}

	public StealthNetPacket recvPacket() throws IOException {
		StealthNetPacket pckt = null;
		String str = dataIn.readLine();
		if (secure) {
			System.out.println("secure");
			System.out.println(str);
			System.out.println(SecureLayer.stob(str));
			System.out.println("test");
			System.out.println(secureLayer.getAESDecrypted(hexDecode(str)));
			System.out.println("test");
		} else {
			//TODO fix this shit pckt = new StealthNetPacket(str);
			
		}
		//System.out.println("RECV: " + new String(pckt.data) + " = " + pckt.toString());
		return pckt;
	}
	
	public static String hexEncode(byte[] pckt){
		StringBuffer buf = new StringBuffer();
		for(int i=0; i<pckt.length; i++){
			int highByte = (pckt[i] >= 0) ? pckt[i] : 256 + pckt[i];
			int lowByte = highByte & 15;
			highByte /= 16;
			buf.append(HEXTABLE[highByte]);
			buf.append(HEXTABLE[lowByte]);
		}
		return buf.toString();
	}
	
	public static byte[] hexDecode(String hexenc){
		if(hexenc.length() % 2 != 0){
			System.err.println("WTF! SOme idiot doesnt know how to encode hex strings");
			return null;
		}
		byte[] ret = new byte[hexenc.length()/2];
		for(int i=0; i<ret.length; i++){
			String abyte = hexenc.substring(2*i, 2*(i+1));//up to but not including arg2
			ret[i] = (byte)Integer.parseInt(abyte, 16);
		}
		return ret;
	}

	public boolean recvReady() throws IOException {
		/*
        System.out.println("Connected: " + commsSocket.isConnected());
        System.out.println("Closed: " + commsSocket.isClosed());
        System.out.println("InClosed: " + commsSocket.isInputShutdown());
        System.out.println("OutClosed: " + commsSocket.isOutputShutdown());
		 */
		return dataIn.ready();
	}
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/

