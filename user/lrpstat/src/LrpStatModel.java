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


// $Revision: 1.14 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/LrpStatModel.java,v 1.14 2002/04/10 19:46:22 hejl Exp $

import java.util.Vector;

/**
 * The class that handles the data (and notifies listeners)
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatModel implements Runnable {
	protected Vector modelListeners;
	protected Vector interfaces;
	protected NetworkConnection con;

	protected boolean stopThread=false;
	protected Vector dataFromNet=null;

	protected int myPort;
	protected String myHost;
	protected int retryCounter = 0;

	/**
	 * Creates an instance of the model that will connect to the
	 * specified host at the specified port and will extract
	 * the information for the specified devices
	 */
	LrpStatModel(String hostname, int port, Vector dev){
		myHost = hostname;
		myPort = port;
	    interfaces = dev;
	    modelListeners = new Vector();
	}

	/**
	 * Adds the specified component to the list of listeners
	 * when new data arrives  "dataArrived" will
	 * be called in the listener
	 * Several listeners can listen on data from the same device
	 */
	public void AddModelListener(LrpStatModelListener l, String deviceName) {
		for (int i =0; i<interfaces.size(); i++) {
			if (((InterfaceOptions)(interfaces.elementAt(i))).deviceName.equals(deviceName)) {
				modelListeners.addElement((Object)l);
				modelListeners.addElement((Object)interfaces.elementAt(i));
				break;
			}
		}
	}

	/**
	 * Removes the specified listener from the list of listeners
	 */
	public  void RemoveModelListener(LrpStatModelListener l) {

		for (int i=0; i<modelListeners.size(); i+=2) {
			if ((LrpStatModelListener)modelListeners.elementAt(i) == l) {
				// Remove the InterfaceOptions for this listener
				modelListeners.removeElementAt(i+1);

				// Remove the listener
				modelListeners.removeElementAt(i);

				break;
			}
		}
	}

	/**
	 * Calls "dataArrived" for each listener
	 * if no data arrived for a specific listener, "null" will be
	 * sent instead of an InterfaceInfo object (that way, the component will be
	 * notified that there's not data for this component
	 */
	public void fireDataChanged() {
		for (int i=0; i<modelListeners.size(); i+=2) {
			String deviceName;
			LrpStatModelListener lst;
			lst = (LrpStatModelListener)modelListeners.elementAt(i);
			deviceName = ((InterfaceOptions)modelListeners.elementAt(i+1)).deviceName;

			lst.dataArrived(new LrpStatModelEvent(this, ((InterfaceOptions)modelListeners.elementAt(i+1)), getDataFor(deviceName)));
		}

	}

	/**
	 * Returns the interface info for the specified device
	 */
	protected InterfaceInfo getDataFor(String deviceName) {
		InterfaceInfo ifInfo;
		if (dataFromNet!=null) {
			for (int i=0; i<dataFromNet.size(); i++) {
				ifInfo = (InterfaceInfo)dataFromNet.elementAt(i);
				if (ifInfo.getName().equals(deviceName)) {
					return(ifInfo);
				}
			}
		}
		return(null);
	}

	/**
	 * Returns the number of miliseconds to wait until a new connection should be established
	 */
	protected long getWaitPeriod(int i) {
		switch (i) {
			case 0: return 10;
			case 1: return 100;
			case 2: return 500;
			default: return 1000;

		}
	}

	/**
	 * Called when the model-thread starts
	 * opens the connection to the server and distributes the data (when data arrives)
	 */
	public void run() {
		stopThread=false;

		con = new NetworkConnection(myHost, myPort);

		while (!stopThread) {
			try {
				Debug.println("Opening connection");
				con.open();

				while (!stopThread) {
					dataFromNet = con.fetchResult();
					if (!stopThread && dataFromNet!=null) {
							retryCounter = 0;
							fireDataChanged();
					} else {
						if (dataFromNet==null) {
							break;
						}
					}

				}
				con.close();
			} catch (Exception e) {
				Debug.println("Exception caught in LrpStatModel.run()");
				Debug.println(e.toString());
				try {
					if (retryCounter < 10) retryCounter++;
					Thread.sleep(getWaitPeriod(retryCounter));
				} catch (InterruptedException ex) {
					Debug.println("Interrupted exception caught in LrpStatModel.run()");
				}
			}

		}
		Debug.println("Exiting LrpStatModel.run()");
		con = null;
	}

	/**
	 * Called by the applet when the thread should stop
	 * setting stopThread to true causes the run-method to exit thereby terminating the
	 * model thread
	 * (remember, stop is called from the applet's thread)
	 */
	public void stop() {
		stopThread=true;
	}

}