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
// $Header: /home/cvs/lrpStat/src/LrpStatHistGraph.java,v 1.14 2002/04/10 19:46:22 hejl Exp $

import java.awt.*;
import java.awt.event.*;

/**
 * Implements a histogram view of the device-data
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatHistGraph extends LrpStatAbstractGraph  {
	LrpStatHistGraph (InterfaceOptions opts) {
		super(opts);
	}

	/**
	 * Paints the component
	 */
	public void paint(Graphics graph) {

		// Create an offscreen-image to paint on (if necessary)
		if (myGraphics == null) {
			offScreenImg = createImage(getSize().width, getSize().height);
			myGraphics = offScreenImg.getGraphics();
		}

		// Draw borders and all the other stuff that's common between all three views
		super.paint(myGraphics);


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

		Rectangle clientRect = getClientRect();

		// if the clientRect.width is 0, we can stop here
		if (clientRect.width == 0) return;

		// Get the maximum value
		long tmpThroughput;

		LongEnumeration longEnum = (LongEnumeration)hist.elements();

		long throughputIn=0;
		long throughputOut=0;

		if (ifOpts.autoScale) {
			if (!ifOpts.accumulate) maxThroughput = ifOpts.minimumScaleValue;
			for (int x=0; longEnum.hasMoreElements(); x+=2) {
				if (longEnum.hasMoreElements()) throughputIn  = longEnum.nextLongElement();  else continue;
				if (longEnum.hasMoreElements()) throughputOut =longEnum.nextLongElement();  else continue;

				if (maxThroughput<throughputIn+throughputOut) {
					maxThroughput=throughputIn+throughputOut;
					nMaxInSize=0;
					nMaxOutSize=0;
				}
			}

			// Make sure we don't get 0 for maxThroughput
			if (maxThroughput<=ifOpts.minimumScaleValue) maxThroughput = ifOpts.minimumScaleValue;
		} else {
			if (maxThroughput != ifOpts.maxThroughput) {
				nMaxInSize=0;
				nMaxOutSize=0;
				maxThroughput = ifOpts.maxThroughput;
			}

		}

		// Move back to the beginning of the enumeration
		longEnum.rewind();

		// reset the input/output values (just to be sure)
		throughputIn=0;
		throughputOut=0;

		// Paint the grid
		if (ifOpts.drawGrid) drawGrid(myGraphics, maxThroughput);


		// Paint the graph
		myGraphics.setColor(LrpStatLook.getDataColor1());
		for (int x=0; longEnum.hasMoreElements(); x+=2) {
			if (longEnum.hasMoreElements()) throughputIn  = longEnum.nextLongElement();  else continue;
			if (longEnum.hasMoreElements()) throughputOut = longEnum.nextLongElement();  else continue;

			int throughputHeight = (int)((throughputIn+throughputOut)*(clientRect.height)/maxThroughput);

			// Do some clipping - just in case the "MaxThroughput" value wasn't realistic
			if (throughputHeight>clientRect.height) throughputHeight=clientRect.height;

			myGraphics.drawLine(clientRect.x+(x/2), clientRect.y+clientRect.height,clientRect.x+(x/2),clientRect.y+clientRect.height-throughputHeight);
		}
		// Paint the footer - throughputIn and throughputOut contains the two newest values
		drawFooter(myGraphics, throughputIn, throughputOut, LrpStatLook.getControlForeground(),maxThroughput);

		graph.drawImage(offScreenImg,0,0,this);
	}

}