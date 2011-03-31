/******************************************************************************
 * ELEC5616/NETS3016
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetServer.java
 * AUTHORS:         Matt Barrie and Stephen Gould
 * DESCRIPTION:     Implementation of StealthNet Server for ELEC5616/NETS3016
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0-ICE
 *
 * REVISION HISTORY:
 *
 *****************************************************************************/

/* Import Libraries **********************************************************/

import java.io.*;
import java.net.*;

/* StealthNetServer Class Definition *****************************************/

public class StealthNetServer {	
	public static void main(String[] args) throws IOException {
		ServerSocket svrSocket = null;
		SecureLayer secureLayer;
		
		//CHEESE
		int sport = StealthNetComms.getDefaultServerPort();
		try{
			sport = Integer.parseInt(args[0]);
		}
		catch(Exception e){
			System.out.println("Using default port, use StealtheNetServer <portnum> to change");
		}
		try {
			svrSocket = new ServerSocket(sport);
		} catch (IOException e) {
			System.err.println("Could not listen on port: " + sport);
			System.exit(1);
		}

		System.out.println("Server [port:" + svrSocket.getLocalPort() + "] online...");
		
		System.out.println("Initialising RSA");
		secureLayer = new SecureLayer();
		secureLayer.selfInitRSA();
		
		System.out.println("RSA Inited " + new String(secureLayer.descMyPublic()));
		
		while (true) {
			new StealthNetServerThread(svrSocket.accept(), secureLayer).start();
			System.out.println("Server accepted connection...");
		}
	}
}

/******************************************************************************
 * END OF FILE:     StealthNetServer.java
 *****************************************************************************/

