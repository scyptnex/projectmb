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
	private int counter;
	
	public static class CommsException extends IOException{
		public CommsException(String message){
			super(message);
		}
	}

	/**public StealthNetComms() {
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
	}**/
	
	public StealthNetComms(SecureLayer sl) {
		commsSocket = null;
		dataIn = null;
		dataOut = null;
		secureLayer = sl;
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
			byte[] data;
		
			/* Get public key */
			data = recvData();
			secureLayer.initRSAYou(data);
			
			/* Send public key */
			sendData(secureLayer.descMyPublic());
				
			/* Get MAC */
			data = recvData();
			secureLayer.initMac(secureLayer.getRSADecrypted(data), true);
			
			/* Send AES */
			secureLayer.selfInitAES();							
			byte[] msg = SecureLayer.byteJoin(secureLayer.descAES(), secureLayer.descIV());
			msg = SecureLayer.byteJoin(msg, secureLayer.getRSADecrypted(data));
			sendData(secureLayer.getRSAEncrypted(msg));
			
			/* Receive IV */
			data = recvData();
			if (!byteEqual(secureLayer.getRSADecrypted(data), secureLayer.descIV()))
			{
				throw new CommsException("IVs do not match!");
			}
			
			counter = 0;
			
		} catch (Exception e) {
			System.err.println("Connection terminated.");
			return false;
		}

		return true;
	}

	public boolean acceptSession(Socket socket) {
		try {
			System.out.println("Accept Session");
			commsSocket = socket;
			dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
			dataIn = new BufferedReader(new InputStreamReader(
					commsSocket.getInputStream()));
			byte[] data;
			byte[] key = new byte[16];
			byte[] iv = new byte[16];
			byte[] tmp = new byte[32];
			byte[] mac = new byte[32];
			
			/* Send public key */
			sendData(secureLayer.descMyPublic());
						
			/* Get public key */
			data = recvData();
			secureLayer.initRSAYou(data);
			
			/* Send MAC */
			secureLayer.selfInitMac(true);
			sendData(secureLayer.getRSAEncrypted(secureLayer.descMAC(true)));
			
			/* Get AES */
			data = recvData();
			SecureLayer.byteSplit(secureLayer.getRSADecrypted(data), tmp, mac);
			SecureLayer.byteSplit(tmp, key, iv);
			secureLayer.initAES(key, iv);
			
			/* Check received MAC is correct */
			if (!byteEqual(mac, secureLayer.descMAC(true)))
			{
				throw new CommsException("MACs do not match!");
			}
			
			/* Send decrypted IV */
			sendData(secureLayer.getRSAEncrypted(iv));
			
			counter = 0;
					
		} catch (Exception e) {
			System.err.println("Connection terminated.");
			return false;
		}
		return true;
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
		if (dataOut == null) return false;
		try {
			byte[] clear = SecureLayer.byteJoin(itob(counter), pckt.toBytes());
		    sendData(secureLayer.sendAES(clear));
		    
		    counter++;
		    if (counter == Integer.MAX_VALUE) counter = 0;
		} catch (SecureLayer.SecurityException e) {
			System.out.println("Security failed on comms");
		}
		return true;
	}

	public StealthNetPacket recvPacket() throws IOException {
		byte[] data = secureLayer.receiveAES(recvData());
		byte[] ctr = new byte[4];
		byte[] rest = new byte[data.length - 4];
		SecureLayer.byteSplit(data, ctr, rest);
		
		if (btoi(ctr) != counter)
		{
			throw new IOException("Replay attack detected");
		}
		
		counter++;
		if (counter == Integer.MAX_VALUE) counter = 0;
		
		return new StealthNetPacket(rest);
	}
	
	private void sendData(byte[] data)
	{
		dataOut.println(hexEncode(data));
	}
	
	private byte[] recvData() throws IOException
	{
		return hexDecode(dataIn.readLine());
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
	
	public static final byte[] itob(int value) {
		return new byte[] {
				(byte)(value >>> 24),
				(byte)(value >>> 16),
				(byte)(value >>> 8),
				(byte)value};
	}
	
	public static final int btoi(byte[] b) {
		int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (b[i] & 0x000000FF) << shift;
        }
        return value;
	}

	public boolean recvReady() throws IOException {
		return dataIn.ready();
	}
	
	public static boolean byteEqual(byte[] a, byte[] b)
	{
		if (a.length != b.length) return false;
		for (int i = 0; i != a.length; ++i)
		{
			if (a[i] != b[i]) return false;
		}
		return true;
	}
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/

