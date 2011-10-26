/* Lrp Network Monitor: Simple network monitor written in Java
   Copyright (C) 2001 Martin Hejl

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


// $Revision: 1.14 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/NetworkConnection.java,v 1.14 2002/04/10 19:46:22 hejl Exp $


import java.net.Socket;
import java.net.UnknownHostException;
import java.lang.InterruptedException;
import java.io.BufferedInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Vector;

/**
 * Implements a socket connection to read the Info from the host<BR>
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class NetworkConnection{
	protected final String END_OF_DATA_MARKER = "#";
	protected Vector vecResult;
	protected InterfaceInfoParser myParser;
	protected int myPort;
	protected StringBuffer strBuf=new StringBuffer();;

	/**
	 * the host name
	 */
	protected String strHost;

	/**
	 * Socket-object
	 */
	protected Socket sockServerConnection;

	/**
	 * Data input stream from the socket
	 */

 	protected BufferedReader in = null;


	/**
	 * Constructor - initializes the socket-connection
	 */
	NetworkConnection(String host, int port){
		myParser = new InterfaceInfoParser();

		strHost = host;
		myPort = port;
	}

	public void open() throws IOException  {
		// Try to open the Socket - if that doesn't work, we can forget the whole program...
		Debug.println("trying to open " + strHost + ":" + myPort);
		try {
			sockServerConnection = new Socket(strHost, myPort);
			in = new BufferedReader(new InputStreamReader(sockServerConnection.getInputStream()));
		} catch (UnknownHostException e) {
			System.err.println("Don't know about host " + strHost);
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't open I/O for the connection to: " + strHost);
			throw(e);
		}
		Debug.println("Socket opened " + strHost + ":" + myPort);

	}

	/**
	 * Listener-method. _must_ be called from a separate thread because it uses a blocking system call
	 * that would lock the application if it was run the event-dispatching thread
	 */
	public Vector fetchResult() {
		String inputLine;

		try {
			strBuf.setLength(0);

			// read until the "end of info" marker (#) is sent
			while ((inputLine = in.readLine()) != null) {
				if (inputLine.equals(END_OF_DATA_MARKER)) {
					break;
				}
				strBuf.append(inputLine);
				strBuf.append("\n");
			}

			//parse and save the response
			if(myParser.parseProcNetDev(strBuf.toString()+ "\n")) {
				return(myParser.getInfo());
			} else {
				Debug.println("No data received");
				return(null);
			}

		} catch (IOException e) {
			System.err.println("IO-Exception caught: " + e);
		}

		return(null);
	}

	/**
     * Closes all open connections
     */
	public void close() {
		try {
			System.err.println("Closing streams and socket");

			in.close();

			sockServerConnection.close();
			System.err.println("socket closed");

			in = null;
			sockServerConnection = null;

		} catch (IOException e) {
			System.err.println("IOException caught: Could not close Streams or Sockets");
		}
		// Do a garbage-collection - so we get rid of the now unused objects
		java.lang.System.gc();
	}
}

