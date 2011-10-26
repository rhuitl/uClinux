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
// $Header: /home/cvs/lrpStat/src/InterfaceInfo.java,v 1.13 2002/03/12 22:19:13 hejl Exp $

/**
 * Class that stores the information received from the host about a specific network device
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class InterfaceInfo {

	// Constants to specify the direction
	public static final int DIRECTION_RECEIVE = 0;
	public static final int DIRECTION_TRANSMIT = 1;
	public static final int ISDN_OFFLINE=0;
	public static final int ISDN_ONLINE=1;
	public static final int ISDN_TRYING=2;


	// Data that's sent from the server
	protected String ifName;
	protected String ifStatus;
	protected boolean bISDNDevice=false;
	protected int     ISDNStatus;
	protected long rBytes;
	protected long rPackets;
	protected long rErrors;
	protected long rDrop;
	protected long rFifo;
	protected long rFrame;
	protected long rCompressed;
	protected long rMulticast;
	protected long tBytes;
	protected long tPackets;
	protected long tErrors;
	protected long tColls;
	protected long tCarrier;
	protected long tDrop;
	protected long tFifo;
	protected long tCompressed;
	protected long timeStamp=0;
	protected CpuStats objStats;



	/**
	 * Create an instance of InterfaceInfo with default values
	 */
	InterfaceInfo() {
		ifName="";
		ifStatus="";
		rBytes=-1;
		rPackets=-1;
		rErrors=-1;
		rDrop=-1;
		rFifo=-1;
		rFrame=-1;
		rCompressed=-1;
		rMulticast=-1;
		tBytes=-1;
		tPackets=-1;
		tErrors=-1;
		tDrop=-1;
		tFifo=-1;
		tCompressed=-1;
		tColls=-1;
		tCarrier=-1;
		bISDNDevice = false;
		ISDNStatus = ISDN_OFFLINE;
		objStats = new CpuStats();
	}

	/**
	 * Create an instance of InterfaceInfo and initialize it with the given values
	 */
	InterfaceInfo(	String if_Name, String if_Status, long r_Bytes, long r_Packets,
					long r_Errors, long r_Drop, long r_Fifo, long r_Frame, long r_Compressed,
					long r_Multicast, long t_Bytes, long t_Packets, long t_Errors,
					long t_Drop, long t_Fifo, long t_Compressed, long t_Colls, long t_Carrier,
					boolean isdn, int isdn_status, long ts) {
		ifName=if_Name;
		ifStatus=if_Status;
		bISDNDevice = isdn;
		ISDNStatus  = isdn_status;

		rBytes=r_Bytes;
		rPackets=r_Packets;
		rErrors=r_Errors;
		rDrop=r_Drop;
		rFifo=r_Fifo;
		rFrame=r_Frame;
		rCompressed=r_Compressed;
		rMulticast=r_Multicast;
		tBytes=t_Bytes;
		tPackets=t_Packets;
		tErrors=t_Errors;
		tDrop=t_Drop;
		tFifo=t_Fifo;
		tCompressed=t_Compressed;
		tColls=t_Colls;
		tCarrier=t_Carrier;
		timeStamp = ts;
		objStats = new CpuStats();
	}

	public void setUser(long l) {
		objStats.setUser(l);
	}

	public void setNice(long l){
		objStats.setNice(l);
	}

	public void setSystem(long l){
		objStats.setSystem(l);
	}


	public void setIdle(long l){
		objStats.setIdle(l);
	}

	public long getSystem() {
		return(objStats.getSystem());
	}

	public long getUser() {
		return(objStats.getUser());
	}

	public long getNice() {
		return(objStats.getNice());
	}

	public long getIdle() {
		return(objStats.getIdle());
	}

	public long getTimestamp() {
		return(timeStamp);
	}

	public void setTimestamp(long t) {
		timeStamp = t;
	}

	public boolean getISDNDevice() {
		return(bISDNDevice);
	}

	public void setISDNDevice(boolean b) {
		bISDNDevice=b;
	}

	public int getISDNStatus() {
		return(ISDNStatus);
	}

	public void setISDNStatus(int i) {
		ISDNStatus=i;
	}

	/**
	 * Return the Bytes information
	 */
	public long getBytes(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (rBytes);
			case DIRECTION_TRANSMIT:
				return (tBytes);
		}
		return -1;
	}

	/**
	 * Return the Packets information
	 */
	public long getPackets(int direction) {
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (rPackets);
			case DIRECTION_TRANSMIT:
				return (tPackets);
		}
		return -1;
	}

	/**
	 * Return the Errors information
	 */
	public long getErrors(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (rErrors);
			case DIRECTION_TRANSMIT:
				return (tErrors);
		}
		return -1;
	}

	/**
	 * Return the Drop information
	 */
	public long getDrop(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (rDrop);
			case DIRECTION_TRANSMIT:
				return (tDrop);
		}
		return -1;
	}

	/**
	 * Return the Fifo information
	 */
	public long getFifo(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (rFifo);
			case DIRECTION_TRANSMIT:
				return (tFifo);
		}
		return -1;
	}

	/**
	 * Return the Frame information
	 * Only for IN, for OUT -1 is returned
	 */
	public long getFrame(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (rFrame);
			case DIRECTION_TRANSMIT:
				return (-1);
		}
		return -1;
	}

	/**
	 * Return the Compressed information
	 */
	public long getCompressed(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (rCompressed);
			case DIRECTION_TRANSMIT:
				return (tCompressed);
		}
		return -1;
	}

	/**
	 * Return the Colls information
	 * Only for OUT, for IN -1 is returned
	 */
	public long getColls(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (-1);
			case DIRECTION_TRANSMIT:
				return (tColls);
		}
		return -1;
	}

	/**
	 * Return the Carrier information
	 * Only for OUT, for IN -1 is returned
	 */
	public long getCarrier(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (-1);
			case DIRECTION_TRANSMIT:
				return (tCarrier);
		}
		return -1;
	}

	/**
	 * Return the Multicast information
	 * Only for IN, for OUT -1 is returned
	 */
	public long getMulticast(int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				return (rMulticast);
			case DIRECTION_TRANSMIT:
				return (-1);
		}
		return -1;
	}

	/**
	 * Return the Interface name
	 */
	public String getName(){
		return(ifName);
	}

	/**
	 * Return the interface status
	 * currently not used
	 */
	public String getStatus(){
		return(ifStatus);
	}


	/**
	 * Set the Bytes information
	 */
	public void setBytes(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				rBytes=l;
				break;
			case DIRECTION_TRANSMIT:
				tBytes=l;
				break;
		}
//		Debug.println(ifName + ":" + direction + " " + l);

	}

	/**
	 * Set the Packets information
	 */
	public void setPackets(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				rPackets=l;
				break;
			case DIRECTION_TRANSMIT:
				tPackets=l;
				break;
		}

	}

	/**
	 * Set the Errors information
	 */
	public void setErrors(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				rErrors=l;
				break;
			case DIRECTION_TRANSMIT:
				tErrors=l;
				break;
		}

	}

	/**
	 * Set the Drop information
	 */
	public void setDrop(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				rDrop=l;
				break;
			case DIRECTION_TRANSMIT:
				tDrop=l;
				break;
		}

	}

	/**
	 * Set the Fifo information
	 */
	public void setFifo(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				rFifo=l;
				break;
			case DIRECTION_TRANSMIT:
				tFifo=l;
				break;
		}

	}

	/**
	 * Set the Frame information
	 */
	public void setFrame(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				rFrame=l;
				break;
			case DIRECTION_TRANSMIT:
				// Do nothing
				break;
		}

	}

	/**
	 * Set the Compressed information
	 */
	public void setCompressed(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				rCompressed=l;
				break;
			case DIRECTION_TRANSMIT:
				tCompressed=l;
				break;
		}

	}

	/**
	 * Set the Multicast information
	 */
	public void setMulticast(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				rMulticast=l;
				break;
			case DIRECTION_TRANSMIT:
				// Do nothing
				break;
		}

	}

	/**
	 * Set the Colls information
	 */
	public void setColls(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				// Do nothing
				break;
			case DIRECTION_TRANSMIT:
				tColls = l;
				break;
		}

	}

	/**
	 * Set the Carrier information
	 */
	public void setCarrier(long l, int direction){
		switch (direction) {
			case DIRECTION_RECEIVE:
				// Do nothing
				break;
			case DIRECTION_TRANSMIT:
				tCarrier = l;
				break;
		}

	}

	/**
	 * Set the interface name
	 */
	public void setName(String s){
		ifName=s;
	}

	/**
	 * Set the interface status (currently not used)
	 */
	public void setStatus(String s){
		ifStatus=s;
	}

	/**
	 * Prints the data to stderr
	 * for debugging only
	 */
	public void dump(){
		Debug.println(""+ifName);
		Debug.println(""+ifStatus);
		Debug.println(""+rBytes);
		Debug.println(""+rPackets);
		Debug.println(""+rErrors);
		Debug.println(""+rDrop);
		Debug.println(""+rFifo);
		Debug.println(""+rFrame);
		Debug.println(""+rCompressed);
		Debug.println(""+rMulticast);
		Debug.println(""+tBytes);
		Debug.println(""+tPackets);
		Debug.println(""+tErrors);
		Debug.println(""+tColls);
		Debug.println(""+tCarrier);
		Debug.println(""+tDrop);
		Debug.println(""+tFifo);
		Debug.println(""+tCompressed);

	}

	/**
	 * Makes sure no negative values are stored in the object
	 */
	public void clipNegative() {
		if (rBytes<0) rBytes=0;
		if (rPackets<0) rPackets=0;
		if (rErrors<0) rErrors=0;
		if (rDrop<0) rDrop=0;
		if (rFifo<0) rFifo=0;
		if (rFrame<0) rFrame=0;
		if (rCompressed<0) rCompressed=0;
		if (rMulticast<0) rMulticast=0;
		if (tBytes<0) tBytes=0;
		if (tPackets<0) tPackets=0;
		if (tErrors<0) tErrors=0;
		if (tDrop<0) tDrop=0;
		if (tFifo<0) tFifo=0;
		if (tCompressed<0) tCompressed=0;
		if (tColls<0) tColls=0;
		if (tCarrier<0) tCarrier=0;
	}
}

