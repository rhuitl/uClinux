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
// $Header: /home/cvs/lrpStat/src/LrpStatBarGraph.java,v 1.14 2002/04/10 19:46:22 hejl Exp $

import java.util.Vector;
import java.awt.*;
import java.awt.event.*;


/**
 * Implements a bar graph view of the device-data
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatBarGraph extends LrpStatAbstractGraph  {
	LrpStatBarGraph (InterfaceOptions opts) {
		super(opts);
	}

	/**
	 * Paint the component
	 */
	public void paint(Graphics graph) {

		// Create an offscreen-image to paint on (if necessary)
		if (myGraphics == null) {
			offScreenImg = createImage(getSize().width, getSize().height);
			myGraphics = offScreenImg.getGraphics();
		}

		// Draw borders and all the other stuff that's common between all three views
		super.paint(myGraphics);


		// Compute the line-height for the current font
		FontMetrics fm;
		fm = myGraphics.getFontMetrics();
		int lineHeight = fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent();

		// If we received a null-value, print the message and exit
		if (hist == null || hist.isEmpty()) {
			myGraphics.setColor(LrpStatLook.getDataColor1());
			myGraphics.drawString("No data", 2*LrpStatLook.getINSETS(), 2*LrpStatLook.getINSETS() + 2*lineHeight);
			graph.drawImage(offScreenImg,0,0,this);
			return;
		}

		LongEnumeration longEnum = (LongEnumeration)hist.elements();
		long throughputIn=0;
		long throughputOut=0;

		// Get the two last values
		if (longEnum.hasMoreElements()) throughputOut =longEnum.lastLongElement();
		if (longEnum.hasPreviousElement()) throughputIn =longEnum.previousLongElement();


		// Get the size of the area to paint on
		Rectangle clientRect = getClientRect();

		// Calculate the width of the labels
		int columnWidth = fm.stringWidth(ifOpts.inCaption + ": ");
		if (fm.stringWidth(ifOpts.outCaption + ": ") > columnWidth) columnWidth = fm.stringWidth(ifOpts.outCaption + ": ");

		int inWidth;
		int outWidth;

		// Scale the throughput paintValue
		inWidth = (int)((throughputIn*(clientRect.width - columnWidth - 2))/ifOpts.maxThroughput);
		outWidth= (int)((throughputOut*(clientRect.width - columnWidth - 2))/ifOpts.maxThroughput);

		// Do some clipping - just in case the "MaxThroughput" paintValue wasn't realistic
		if (inWidth>(clientRect.width - columnWidth - 2)) inWidth=(clientRect.width - columnWidth- 2);
		if (outWidth>(clientRect.width - columnWidth- 2)) outWidth=(clientRect.width - columnWidth- 2);

		// Draw the footer
		drawFooter(myGraphics, throughputIn, throughputOut, LrpStatLook.getControlForeground(), ifOpts.maxThroughput);


		// Clip the Bars, if neccessary
		if (clientRect.y + 2 + 2*lineHeight < clientRect.y + clientRect.height) {

			// Draw the labels
			myGraphics.setColor(LrpStatLook.getDataColor1());
			myGraphics.drawString(ifOpts.inCaption + ":", clientRect.x, clientRect.y + lineHeight+ 2);
			myGraphics.drawString(ifOpts.outCaption + ":",clientRect.x , clientRect.y + 2*lineHeight + 4);

			// Draw the bars
			myGraphics.setColor(LrpStatLook.getBarBackground());
			myGraphics.fillRect(clientRect.x +columnWidth, clientRect.y+2,(clientRect.width - columnWidth - 2), lineHeight);
			myGraphics.fillRect(clientRect.x +columnWidth, clientRect.y+ lineHeight +4,(clientRect.width - columnWidth- 2), lineHeight);

			myGraphics.setColor(LrpStatLook.getDataColor1());
			myGraphics.fillRect(clientRect.x +columnWidth, clientRect.y+2,inWidth, lineHeight);
			myGraphics.fillRect(clientRect.x +columnWidth, clientRect.y+ lineHeight+4,outWidth, lineHeight);
		}

		// Paint the offscreen-image to the actual graphics context
		graph.drawImage(offScreenImg,0,0,this);

	}

}