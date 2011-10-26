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
// $Header: /home/cvs/lrpStat/src/LrpStatNumericGraph.java,v 1.14 2002/04/10 19:46:22 hejl Exp $

import java.util.Vector;
import java.awt.*;
import java.awt.event.*;

/**
 * Implements a text only view of the device-data
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatNumericGraph extends LrpStatAbstractGraph {
	//protected InterfaceInfo paintValue=null;

	LrpStatNumericGraph(InterfaceOptions opts) {
		super(opts);
	}

	public void paint(Graphics graph) {

		// Create an offscreen-image to paint on (if necessary)
		if (myGraphics == null) {
			offScreenImg = createImage(getSize().width, getSize().height);
			myGraphics = offScreenImg.getGraphics();
		}

		// Draw borders and all the other stuff that's common between all three views
		super.paint(myGraphics);

		Rectangle clientRect = getClientRect();


		FontMetrics fm;
		fm = myGraphics.getFontMetrics();

		int lineHeight = fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent();

		// If we received a null-value, print the message and exit
		if (hist == null) {
			myGraphics.setColor(LrpStatLook.getDataColor1());
			myGraphics.drawString("No data", clientRect.x, clientRect.y + lineHeight);
			graph.drawImage(offScreenImg,0,0,this);
			return;
		}

		LongEnumeration longEnum = (LongEnumeration)hist.elements();

		long throughputIn=0;
		long throughputOut=0;

		// Get the two last values
		if (longEnum.hasMoreElements()) throughputOut =longEnum.lastLongElement();
		if (longEnum.hasPreviousElement()) throughputIn =longEnum.previousLongElement();

		// Paint the labels
		int columnWidth = fm.stringWidth("In: ");
		if (fm.stringWidth("Out: ") > columnWidth) columnWidth = fm.stringWidth("Out: ");

		drawFooter(myGraphics, throughputIn , throughputOut, LrpStatLook.getControlForeground(), ifOpts.maxThroughput);

		graph.drawImage(offScreenImg,0,0,this);
	}

}