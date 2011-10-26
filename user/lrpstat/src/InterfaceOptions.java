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
// $Header: /home/cvs/lrpStat/src/InterfaceOptions.java,v 1.13 2002/03/12 22:19:13 hejl Exp $

import java.util.Vector;

/**
 * Class that holds the information gathered from the parameters given to the applet
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class InterfaceOptions {
//	public static final long DEVICE_TYPE_STATIC = 1;
//	public static final long DEVICE_TYPE_DYNAMIC = 2;
//	public long deviceType;

	public final long minimumScaleValue=1;
	public String deviceName;
	public String deviceLabel;
	public boolean useISDN=false;
	public long maxThroughput;
	public String controlType;
	public Vector actions=new Vector();
	public long gridInterval=0;
	public long gridLineCount=0;
	public boolean drawGrid=false;
	public boolean drawLegend=false;
	public boolean autoScale=false;
	public boolean accumulate=false;
	public boolean drawTitle=true;
	public boolean drawStatus=true;
	public boolean dontNormalize=false;
	public boolean percentValue=false;
	public boolean absoluteValue=false;
//	public boolean isCPU=false;
	public String inCaption="In";
	public String outCaption="Out";
	public boolean displayCPUUsage=false;
	public long inOffset=0;
	public long outOffset=0;
	public int tickInterval=10;
	public boolean drawTicks=false;

}
