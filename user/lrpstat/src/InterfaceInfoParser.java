import java.util.Vector;
import java.util.StringTokenizer;
import java.util.Calendar;


// Lrp Network Monitor: Simple network monitor written in Java
// Copyright (C) 2001 Martin Hejl
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

// $Revision: 1.13 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/InterfaceInfoParser.java,v 1.13 2002/03/12 22:19:13 hejl Exp $

/**
 * Class that parses the output of cat /proc/net/dev
 * and also cat /dev/isdninfo and cat /dev/stats
 * <PRE>Protocol format for protocol-version 1.20 (only supported by the c-component):
 * Line 1: ProtocolVersion timestamp cpuSystem cpuUser cpuNice cpuIdle
 * Line 2: ISDNDeviceName1:ONLINE|OFFLINE ISDNDeviceName2:ONLINE|OFFLINE ...
 * Line 3..n: deviceName:InBytes InPackets InErrors InDrop InFifo InFrame InCompressed InMulticast OutBytes OutPackets OutErrors OutDrop OutFifo OutCollisions OutCarrier OutCompressed
 * </PRE>
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class InterfaceInfoParser {

	protected boolean errorOccurred=false;
	protected Vector interfaces=new Vector();
	protected long lVersion=100;
	protected long lTimestamp;
	protected String strIsdnDeviceName="";
	protected InterfaceOptions ifOpts;
	protected long lUser;
	protected long lNice;
	protected long lSystem;
	protected long lIdle;

	InterfaceInfoParser() {
		ifOpts = new InterfaceOptions();
	}

	InterfaceInfoParser(InterfaceOptions opts) {
		ifOpts = opts;
	}

	/**
	 * parses the output from "cat /proc/net/dev" and stores the information in the Vector
	 */
	public boolean parseProcNetDev(String s) {
		interfaces.removeAllElements();
		InterfaceInfo ifInformation;
		String strHeader;
		String strISDNInfo;

		lTimestamp = Calendar.getInstance().getTime().getTime();
		strISDNInfo="";
		lVersion = 100;

		// Skip the first two lines and parse the header

		StringTokenizer st = new StringTokenizer(s, "\n");
		String str="";
		String ss;

		if (st.hasMoreTokens()) {
			strHeader = st.nextToken();
			if (strHeader.length() > 1) parseHeader(strHeader);
		} else {
			logParseError(s, "header" , "");
			return false;
		}

		if (st.hasMoreTokens()) {
			if (lVersion>100)  {
				strISDNInfo = st.nextToken();
			} else {
				// Dump the contents of this token
				st.nextToken();
			}
		} else {
			logParseError(s, "isdnVersion", "");
			return false;
		}

		// Get rid of all newlines
		while (st.hasMoreTokens()) {
			ss = st.nextToken();
			str=str + ss.trim() + " ";
		}

		/**
		 * Convert the string into tokens (separator is space or ":")
		 */

		st = new StringTokenizer(str,": ");

		/**
		 * Read all the fields from the output
		 */
        while (st.hasMoreTokens()) {
			ifInformation = new InterfaceInfo();

			ifInformation.setTimestamp(lTimestamp);
			ifInformation.setUser(lUser);
			ifInformation.setSystem(lSystem);
			ifInformation.setNice(lNice);
			ifInformation.setIdle(lIdle);


			if (st.hasMoreTokens())	{
				ifInformation.setName(st.nextToken().toLowerCase());
			} else {
				logParseError(s, "name", "");
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setBytes(atol(st.nextToken()),InterfaceInfo.DIRECTION_RECEIVE );
			} else {
				logParseError(s, "inBytes",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setPackets(atol(st.nextToken()),InterfaceInfo.DIRECTION_RECEIVE );
			} else {
				logParseError(s, "inPackets",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setErrors(atol(st.nextToken()),InterfaceInfo.DIRECTION_RECEIVE );
			} else {
				logParseError(s, "inErrors",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setDrop(atol(st.nextToken()),InterfaceInfo.DIRECTION_RECEIVE );
			} else {
				logParseError(s, "inDrop",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setFifo(atol(st.nextToken()),InterfaceInfo.DIRECTION_RECEIVE );
			} else {
				logParseError(s, "inFifo",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setFrame(atol(st.nextToken()),InterfaceInfo.DIRECTION_RECEIVE );
			} else {
				logParseError(s, "inFrame",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setCompressed(atol(st.nextToken()),InterfaceInfo.DIRECTION_RECEIVE );
			} else {
				logParseError(s, "inCompressed",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setMulticast(atol(st.nextToken()),InterfaceInfo.DIRECTION_RECEIVE );
			} else {
				logParseError(s, "inMulticast",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setBytes(atol(st.nextToken()),InterfaceInfo.DIRECTION_TRANSMIT);
			} else {
				logParseError(s, "outBytes",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setPackets(atol(st.nextToken()),InterfaceInfo.DIRECTION_TRANSMIT);
			} else {
				logParseError(s, "outPackets",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setErrors(atol(st.nextToken()),InterfaceInfo.DIRECTION_TRANSMIT);
			} else {
				logParseError(s, "outErrors",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setDrop(atol(st.nextToken()),InterfaceInfo.DIRECTION_TRANSMIT);
			} else {
				logParseError(s, "outDrop",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setFifo(atol(st.nextToken()),InterfaceInfo.DIRECTION_TRANSMIT);
			} else {
				logParseError(s, "outFifo",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setColls(atol(st.nextToken()),InterfaceInfo.DIRECTION_TRANSMIT);
			} else {
				logParseError(s, "outColls",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setCarrier(atol(st.nextToken()),InterfaceInfo.DIRECTION_TRANSMIT);
			} else {
				logParseError(s, "outCarrier",ifInformation.getName());
				return false;
			}

			if (st.hasMoreTokens())	{
				ifInformation.setCompressed(atol(st.nextToken()),InterfaceInfo.DIRECTION_TRANSMIT);
			} else {
				logParseError(s, "outCompressed",ifInformation.getName());
				return false;
			}

			/**
			 * If all fields could be parsed without error, add the object to the vector
			 */
			interfaces.addElement((Object)ifInformation);
          }

          // Ok, now we have all devices, so we can parse the isdn-info,
          // and add the information to that object
          if (lVersion>100) parseIsdnInfo(strISDNInfo);

          return true;
	}

	/**
	 * Parses the header line
	 */
	protected void parseHeader(String s) {
		StringTokenizer st = new StringTokenizer(s, " ");
		long ts;
		if (st.hasMoreTokens()) {
			lVersion = atol(st.nextToken());
		}

		if (st.hasMoreTokens()) {
			ts = atol(st.nextToken());
			if (ts>0) lTimestamp=ts;
		}

		if (lVersion>=120){
			if (st.hasMoreTokens()) lSystem = atol(st.nextToken()); else lSystem=0;
			if (st.hasMoreTokens()) lUser = atol(st.nextToken()); else lUser=0;
			if (st.hasMoreTokens()) lNice = atol(st.nextToken()); else lNice=0;
			if (st.hasMoreTokens()) lIdle = atol(st.nextToken()); else lIdle=100;


		}



	}

	/**
	 * Parses the output of /dev/isdninfo
	 * Not implemented yet
	 */
	public void parseIsdnInfo(String s) {
		StringTokenizer devices = new StringTokenizer(s, " ");
		StringTokenizer st;
		String deviceName;
		String deviceStatus;

		while (devices.hasMoreTokens()) {
			st = new StringTokenizer(devices.nextToken(), ":");
			if (st.hasMoreTokens()) {
				deviceName = st.nextToken();
				if (st.hasMoreTokens()) {
					deviceStatus = st.nextToken();
					setISDNInfo(deviceName, deviceStatus);
				}
			}
		}

	}

	protected void setISDNInfo(String deviceName, String deviceStatus){
		InterfaceInfo ifInfo;

		if (deviceName==null || deviceStatus==null || deviceName.equals("") || deviceStatus.equals(""))  return;

		for (int i=0; i<interfaces.size(); i++) {
			ifInfo = (InterfaceInfo)interfaces.elementAt(i);
			if (ifInfo.getName().equals(deviceName)) {
				ifInfo.setISDNDevice(true);
				if (deviceStatus.equals("OFFLINE")) ifInfo.setISDNStatus(InterfaceInfo.ISDN_OFFLINE);
				if (deviceStatus.equals("ONLINE")) ifInfo.setISDNStatus(InterfaceInfo.ISDN_ONLINE);
				if (deviceStatus.equals("TRYING")) ifInfo.setISDNStatus(InterfaceInfo.ISDN_TRYING);
				return;
			}
		}

	}
	/**
	 * Returns the list of interfaces and their information
	 * this should only be called _after_ some output has been parsed
	 */
	public Vector getInfo(){
		return(interfaces);
	}

	/**
	 * Helper function. Converts a string into the corresponding long value
	 * Errors are handled internally, if an error occurs, the value -1 is returned
	 * (which is ok here, than we'll never have negative traffic on an interface)
	 */
	private long atol(String s) {
		try {
			return(Long.valueOf(s).longValue());
		} catch (NumberFormatException ex) {
			return (-1);
		}
	}

	/**
	 * Prints an error message to stderr
	 */
	private void logParseError(String strInput, String position, String devName) {
		if (!errorOccurred) System.err.println("Unexpected end of data while trying to parse:\n" + strInput + "\n" + devName + " " + position );
		errorOccurred=true;
	}
}

