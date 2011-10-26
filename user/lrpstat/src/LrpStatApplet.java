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
// $Header: /home/cvs/lrpStat/src/LrpStatApplet.java,v 1.13 2002/03/12 22:19:13 hejl Exp $

import java.applet.Applet;
import java.util.Vector;
import java.awt.*;
import java.awt.event.*;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * the applet that displays the network data see Readme.txt for a description
 * of supported parameters for the applet
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatApplet extends Applet{
	protected NetworkConnection con;
	protected Vector v;
	protected int serverPort=0;
	protected Vector interfaceOptionsList;
	protected String strHostname;
	protected LrpStatModel myModel;
	protected InterfaceInfo myData;
	protected long deviceCount=0;
	protected Thread modelListener;
	protected Vector controls;
	protected boolean useVerticalAlignment; //=true;

	/**
	 * Pasrse the parameters given in the HTML file
	 */
	protected void parseParameters(){
		String strDummy;
		InterfaceOptions opts;

		Color tmpColor;

		// Get the hostname of the machine to monitor
		strHostname = getCodeBase().getHost();

		// Get the port to fetch the info from
		serverPort = getIntParameter("INFOPORT",60183);

		// Set alignment
		// --> Changed, since it didn't comply with the documentation...
		//useVerticalAlignment= getBoolParameter("ALIGNMENT", true);
		useVerticalAlignment= getStringParameter("ALIGNMENT", "Y").toUpperCase().equals("Y");

		// Get Title Font name
		LrpStatLook.setTitleFontName(getStringParameter("TITLE_FONT_NAME", LrpStatLook.getTitleFontName()));

		// Get Title Font size
		LrpStatLook.setTitleFontSize(getIntParameter("TITLE_FONT_SIZE",LrpStatLook.getTitleFontSize()));

		// Get Title Font name
		LrpStatLook.setStatusFontName(getStringParameter("STATUS_FONT_NAME",LrpStatLook.getStatusFontName()));

		// Get Title Font size
		LrpStatLook.statusFontSize = getIntParameter("STATUS_FONT_SIZE",LrpStatLook.statusFontSize);

		// Should the client-border be drawn?
		LrpStatLook.drawClientBorder = getBoolParameter("DRAW_CLIENT_BORDER", LrpStatLook.drawClientBorder);

		// Should the component-border be drawn?
		LrpStatLook.setDrawComponentBorder(getBoolParameter("DRAW_COMPONENT_BORDER",LrpStatLook.getDrawComponentBorder()));

		// Parse the user-specified colors
		LrpStatLook.setControlBackground(getColorParameter("CONTROL_BACKGROUND_COLOR",LrpStatLook.getControlBackground()));
		LrpStatLook.setControlForeground(getColorParameter("CONTROL_FOREGROUND_COLOR",LrpStatLook.getControlForeground()));
		LrpStatLook.setDataOnlineBackground(getColorParameter("DATA_BACKGROUND_COLOR",LrpStatLook.getDataOnlineBackground()));
		LrpStatLook.setDataTryingBackground(getColorParameter("DATA_BACKGROUND_TRYING_COLOR",LrpStatLook.getDataTryingBackground()));
		LrpStatLook.setDataOfflineBackground(getColorParameter("DATA_BACKGROUND_OFFLINE_COLOR",LrpStatLook.getDataOfflineBackground()));
		LrpStatLook.setDataColor1(getColorParameter("DATA_FOREGROUND_COLOR1",LrpStatLook.getDataColor1()));
		LrpStatLook.setDataColor2(getColorParameter("DATA_FOREGROUND_COLOR2",LrpStatLook.getDataColor2()));
		LrpStatLook.setGridColor(getColorParameter("GRID_COLOR",LrpStatLook.getGridColor()));
		LrpStatLook.setBarBackground(getColorParameter("BAR_BACKGROUND_COLOR",LrpStatLook.getBarBackground()));

		LrpStatLook.setCpuSystemColor(getColorParameter("CPU_SYSTEM_COLOR",LrpStatLook.getCpuSystemColor()));
		LrpStatLook.setCpuIdleColor(getColorParameter("CPU_IDLE_COLOR",LrpStatLook.getCpuIdleColor()));
		LrpStatLook.setCpuUserColor(getColorParameter("CPU_USER_COLOR",LrpStatLook.getCpuUserColor()));
		LrpStatLook.setCpuNiceColor(getColorParameter("CPU_NICE_COLOR",LrpStatLook.getCpuNiceColor()));


		// Get INSETS
		LrpStatLook.setINSETS(getIntParameter("INSETS", LrpStatLook.getINSETS()));
		if (LrpStatLook.getINSETS()<0) LrpStatLook.setINSETS(0);

		interfaceOptionsList = new Vector();
		int i;
		i = 0;

		// Read the parameters for the Interface and store those infos in the Vector "interfaceOptionsList"
		while (getParameter("DEV" + i + "_NAME") != null) {
			opts = new InterfaceOptions();
			opts.deviceName = getStringParameter("DEV" + i + "_NAME","").toLowerCase();
			opts.deviceLabel = getStringParameter("DEV" + i + "_LABEL", null);
			if (opts.deviceLabel==null) opts.deviceLabel= opts.deviceName;

			opts.controlType = getStringParameter("DEV" + i + "_MODE","numeric");
			opts.inOffset = getLongParameter("DEV" + i + "_IN_OFFSET",0);
			if (opts.inOffset<0) opts.inOffset =0;

			opts.outOffset = getLongParameter("DEV" + i + "_OUT_OFFSET",0);
			if (opts.outOffset<0) opts.outOffset =0;

			opts.drawTicks = getBoolParameter("DEV" + i + "_DRAW_TICKS", opts.drawTicks);
			opts.tickInterval = getIntParameter("DEV" + i + "_TICK_INTERVAL", opts.tickInterval);

			opts.drawLegend = getBoolParameter("DEV" + i + "_DRAW_LEGEND", opts.drawLegend);
			opts.drawTitle = getBoolParameter("DEV" + i + "_DRAW_TITLE",opts.drawTitle);
			opts.drawStatus = getBoolParameter("DEV" + i + "_DRAW_STATUS",opts.drawStatus);

			opts.dontNormalize = getBoolParameter("DEV" + i + "_DONT_NORMALIZE",opts.dontNormalize);
			opts.absoluteValue = getBoolParameter("DEV" + i + "_ABSOLUTE",opts.absoluteValue);
			opts.percentValue = getBoolParameter("DEV" + i + "_PERCENT",opts.absoluteValue);

			opts.inCaption = getStringParameter("DEV" + i + "_IN_CAPTION",opts.inCaption);
			opts.outCaption = getStringParameter("DEV" + i + "_OUT_CAPTION",opts.outCaption);

			// Should the cpu-usage be displayed?
			opts.displayCPUUsage = getBoolParameter("DEV" + i + "_SHOW_CPU_USAGE",opts.displayCPUUsage);

			// Fetch the options for DEXx_MAX
			// This is a little messy, because of the "auto" and "auto_accumulate" option
			if (getParameter("DEV" + i + "_MAX") == null || getParameter("DEV" + i + "_MAX").toLowerCase().equals("auto") || getParameter("DEV" + i + "_MAX").toLowerCase().equals("auto_accumulate")) {
				if (opts.controlType.equals("bar") || opts.controlType.equals("numeric")) {
					System.err.println("Autoscale not supported for bar-view or numeric view");
					opts.autoScale = false;

					// Set a dummy value so we don't get a division by zero
					opts.maxThroughput = opts.minimumScaleValue;
				} else {
					Debug.println("Setting Autoscale for DEV_" + i);
					opts.autoScale = true;
					if (getParameter("DEV" + i + "_MAX") == null || !getParameter("DEV" + i + "_MAX").toLowerCase().equals("auto_accumulate")) {
						opts.accumulate = false;
					} else {
						opts.accumulate = true;
					}

				}
			} else {
				opts.autoScale = false;
				opts.maxThroughput = atol(getParameter("DEV" + i + "_MAX"));
				Debug.println("Setting scale for DEV_" + i + " to " + opts.maxThroughput );
			}

			// Get the GRID info
			strDummy = getParameter("DEV" + i + "_GRID_INTERVAL");

			if (strDummy==null) {
				opts.drawGrid = false;
				opts.gridInterval=0;
			} else {
				opts.drawGrid = true;
				opts.gridInterval = atol(strDummy);
				if (opts.gridInterval <= 0) {
					opts.drawGrid = false;
					System.err.println("Malformed value " + strDummy + " for Parameter " + "DEV" + i + "_GRID_INTERVAL");
				}
			}

			strDummy = getParameter("DEV" + i + "_GRID_LINECOUNT");
			if (strDummy==null) {
				// no need to set drawGrid to false - because it will already be set to false
				// if not value for GRID_INTERVAL is given
			} else {
				long linecount = atol(strDummy);
				if (linecount < 0) {
					opts.drawGrid = false;
					System.err.println("Malformed value " + strDummy + " for Parameter " + "DEV" + i + "_GRID_LINECOUNT");
				} else {
					opts.drawGrid = true;
					opts.gridLineCount = linecount;
				}
			}

			// Get the type of the interface
			// Currently, not used
//			strDummy = getParameter("DEV" + i + "_TYPE");
//			if (strDummy.toLowerCase().equals("static")) opts.deviceType = InterfaceOptions.DEVICE_TYPE_STATIC; else opts.deviceType = InterfaceOptions.DEVICE_TYPE_DYNAMIC;

			CommandInfo ci;
			int l=0;

			// Read the actions (if defined) for this interface
			while (getParameter("DEV" + i + "_ACTION" + l) != null){
				strDummy = getParameter("DEV" + i + "_ACTION" + l);

				ci = new CommandInfo();
				ci.caption = strDummy.substring(0, strDummy.indexOf(";"));
				strDummy = strDummy.substring(strDummy.indexOf(";")+1).trim();

				if (strDummy.toLowerCase().startsWith("get"))  {
					ci.commandType = CommandInfo.COMMAND_TYPE_GET;
					strDummy = strDummy.substring(3).trim();
					try {
						ci.commandURL = new URL("http://" + getCodeBase().getHost() + strDummy);
					} catch (java.net.MalformedURLException e) {
						System.err.println("Malformed URL " + strDummy + " for Parameter " + "DEV" + i + "_ACTION" + l);
						ci = null;
					}

				} else {
					if (strDummy.toLowerCase().startsWith("open")) {
						ci.commandType = CommandInfo.COMMAND_TYPE_OPEN;
						strDummy = strDummy.substring(4).trim();
						ci.commandHost = getCodeBase().getHost();
						ci.commandPort = atol(strDummy);
						if (ci.commandPort <= 0) {
							System.err.println("Illegal port " + strDummy + " for Parameter " + "DEV" + i + "_ACTION" + l);
							ci=null;
						}
					}
				}
				// If the could be generated, add it to the Vector
				if (ci != null) opts.actions.addElement((Object)ci);
				l++;
			}

			// Make sure we don't normalize percent Values
			// Max for Percent is always 100
			if (opts.percentValue) {
				opts.dontNormalize = true;
				opts.autoScale = false;
				opts.maxThroughput = 100;
			}

			interfaceOptionsList.addElement((Object)opts);
			deviceCount++;
			i++;
		}

	}

	// Create the objects that correspond to the parameters given in the HTML file
 	public void init() {
		parseParameters();

		myModel = new LrpStatModel(strHostname, serverPort, interfaceOptionsList);

		String controlType;
		String ifName;


		if (useVerticalAlignment) {
			setLayout(new GridLayout(interfaceOptionsList.size(),0));
		} else {
			setLayout(new GridLayout(0,interfaceOptionsList.size()));
		}

		controls = new Vector();

		for (int i=0; i<interfaceOptionsList.size(); i++) {
			ifName = ((InterfaceOptions)interfaceOptionsList.elementAt(i)).deviceName;
			controlType = ((InterfaceOptions)interfaceOptionsList.elementAt(i)).controlType;
			if (controlType.equals("histogram")) {
				LrpStatHistGraph myGraph = new LrpStatHistGraph((InterfaceOptions)interfaceOptionsList.elementAt(i));
				myModel.AddModelListener(myGraph, ifName);
				add(myGraph);
				controls.addElement(myGraph);
			} else
			if (controlType.equals("bar")) {
				LrpStatBarGraph myGraph = new LrpStatBarGraph((InterfaceOptions)interfaceOptionsList.elementAt(i));
				myModel.AddModelListener(myGraph, ifName);
				add(myGraph);
				controls.addElement(myGraph);
			} else
			if (controlType.equals("line")) {
				LrpStatLineGraph myGraph = new LrpStatLineGraph((InterfaceOptions)interfaceOptionsList.elementAt(i));
				myModel.AddModelListener(myGraph, ifName);
				add(myGraph);
				controls.addElement(myGraph);
			} else
			if (controlType.equals("doublehistogram")) {
				LrpStatDoubleHistGraph myGraph = new LrpStatDoubleHistGraph((InterfaceOptions)interfaceOptionsList.elementAt(i));
				myModel.AddModelListener(myGraph, ifName);
				add(myGraph);
				controls.addElement(myGraph);
			} else
			{
			// numeric is the default
				LrpStatNumericGraph myGraph = new LrpStatNumericGraph((InterfaceOptions)interfaceOptionsList.elementAt(i));
				myModel.AddModelListener(myGraph, ifName);
				add(myGraph);
				controls.addElement(myGraph);
			}
		}

		setBackground(LrpStatLook.getControlBackground());

		// Now force all controls to re-layout themselves
		for (int i=0; i<controls.size(); i++) {
				((ComponentListener)controls.elementAt(i)).componentResized(new ComponentEvent(this, 0));
		}

	}

	/**
	 * Called by the browser to start the applet
	 */
	public void start(){
		// If a serverPort was given, start the model-thread
		if (serverPort!=0) {
			modelListener = new Thread(myModel);
			modelListener.setDaemon(true);
			modelListener.start();
		}

	}

	/**
	 * Called by the browser to stop the applet
	 */
	public void stop() {
		if (serverPort!=0) {
			myModel.stop();

			try {
				// Make sure the listener thread ends - otherwise,
				// because of the strange way Netscape handles resizing of windows
				// (sending lots of Start and Stop messages), the new thread might be
				// started before the old one has terminates - causing all kinds of
				// troubles
				modelListener.join();
			} catch (InterruptedException e) {}
			modelListener=null;
		}
	}


	// Ok, not the perfect way to do this, but it works here (-1 is not a
	// probable value to occur, so we can misuse it for errors)
	private long atol(String s) {
		if (s==null) return(0);
		try {
			return(Long.valueOf(s).longValue());
		} catch (NumberFormatException ex) {
			return (-1);
		}
	}

	// Helper functions to clean up the parsing part of the applet

	public boolean getBoolParameter(String paramName, boolean defaultValue) {
		String strDummy;
		if ((strDummy = getParameter(paramName)) == null) return(defaultValue);
		if (strDummy.equals("0")) return(false);
		if (strDummy.equals("false")) return(false);
		return(true);

	}

	public String getStringParameter(String paramName, String defaultValue) {
		String strDummy;
		if ((strDummy = getParameter(paramName)) == null) return(defaultValue);
		return(strDummy);

	}

	public long getLongParameter(String paramName, long defaultValue) {
		String strDummy;

		if ((strDummy = getParameter(paramName)) == null) return(defaultValue);

		try {
			return(Long.parseLong(strDummy));
		} catch (NumberFormatException ex) {
			return(defaultValue);
		}
	}

	public int getIntParameter(String paramName, int defaultValue) {
		String strDummy;

		if ((strDummy = getParameter(paramName)) == null) return(defaultValue);

		try {
			return(Integer.parseInt(strDummy));
		} catch (NumberFormatException ex) {
			return(defaultValue);
		}
	}

	public Color getColorParameter(String paramName, Color defaultValue) {
		Color tmpColor;
		if (getParameter(paramName)!=null) {
			if ((tmpColor = LrpStatLook.parseColor(getParameter(paramName))) !=null) {
				return(tmpColor);
			}
		}
		return(defaultValue);
	}
}