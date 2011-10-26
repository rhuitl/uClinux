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
// $Header: /home/cvs/lrpStat/src/LrpStatLineGraph.java,v 1.14 2002/04/10 19:46:22 hejl Exp $

import java.util.Vector;
import java.awt.*;
import java.awt.event.*;


/**
 * Implements a histogram view of the device-data
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatLineGraph extends LrpStatAbstractGraph  {
	//LongRingBuffer hist;

	LrpStatLineGraph(InterfaceOptions opts) {
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

		FontMetrics fm;
		fm = myGraphics.getFontMetrics();


		if (lineHeight==0) lineHeight = fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent();

		// If we received a null-value, print the message and exit
		if (hist == null || hist.isEmpty()) {
			myGraphics.setColor(LrpStatLook.getDataColor1());
			myGraphics.drawString("No data", 2*LrpStatLook.INSETS, 2*LrpStatLook.getINSETS() + 2*lineHeight);
			graph.drawImage(offScreenImg,0,0,this);
			return;
		}

		Rectangle clientRect = getClientRect();

		// if the clientRect.width is 0, we can stop here
		if (clientRect.width == 0) return;


		// Get the maximum value
		long tmpThroughput;

		if (ifOpts.autoScale) {
			if (!ifOpts.accumulate) maxThroughput = ifOpts.minimumScaleValue;
			if (maxThroughput<hist.max()) {
				nMaxInSize=0;
				nMaxOutSize=0;
				maxThroughput=hist.max();
			}

			// Make sure we don't get 0 for maxThroughput
			if (maxThroughput<=ifOpts.minimumScaleValue)
			{
				nMaxInSize=0;
				nMaxOutSize=0;
				maxThroughput = ifOpts.minimumScaleValue;
			}
		} else {
			if (maxThroughput != ifOpts.maxThroughput) {
				nMaxInSize=0;
				nMaxOutSize=0;
				maxThroughput = ifOpts.maxThroughput;
			}
		}

		if (ifOpts.drawGrid) drawGrid(myGraphics, maxThroughput);

		// Get the current inValue and outValue
		long throughputIn; //=hist.elementAt(hist.getElementCount()-2);
		long throughputOut; //=hist.elementAt(hist.getElementCount()-1);
		long throughputIn2;
		long throughputOut2;

		// Paint the line for "in"
		myGraphics.setColor(LrpStatLook.getDataColor1());

		LongEnumeration longEnum = (LongEnumeration)hist.elements();

		// Read the first element
		if (longEnum.hasMoreElements()) {
			throughputIn2  = longEnum.nextLongElement();
		} else {
			System.err.println("No DATA 1a !!");return;
		}

		// Skip the second
		if (longEnum.hasMoreElements()) {
			longEnum.nextLongElement();
		} else {
			System.err.println("No DATA 1b !!");
			return;
		}

		for (int x=0; longEnum.hasMoreElements() ; x+=2) {
			throughputIn = throughputIn2;
			if (longEnum.hasMoreElements()) throughputIn2=longEnum.nextLongElement();  else continue;
			if (longEnum.hasMoreElements()) longEnum.nextLongElement();

			int throughputHeightIn = (int)((throughputIn)*(clientRect.height)/maxThroughput);
			int throughputHeightIn2 = (int)((throughputIn2)*(clientRect.height)/maxThroughput);

			// Do some clipping - just in case the "MaxThroughput" value wasn't realistic
			if (throughputHeightIn>clientRect.height) throughputHeightIn=clientRect.height;
			if (throughputHeightIn2>clientRect.height) throughputHeightIn2=clientRect.height;

			myGraphics.drawLine(	clientRect.x+x/2,
						clientRect.y+clientRect.height-throughputHeightIn,
						clientRect.x+x/2+1,
						clientRect.y+clientRect.height-throughputHeightIn2);
		}

		longEnum.rewind();

		// Only draw the second line for values that don't show a percentage
//		if (ifOpts.percentValue) {
//			//Debug.println("Not painting out");
//			throughputOut2=0;
//		} else {
			// Paint the line for "out"
			myGraphics.setColor(LrpStatLook.getDataColor2());

			// Skip the first element
			if (longEnum.hasMoreElements()) longEnum.nextLongElement(); else {System.err.println("No DATA 2a!!");return;}

			// Read the second
			if (longEnum.hasMoreElements()) throughputOut2 = longEnum.nextLongElement(); else {System.err.println("No DATA 2b!!");return;}
			for (int x=0; longEnum.hasMoreElements(); x+=2) {
				throughputOut = throughputOut2;
				if (longEnum.hasMoreElements()) longEnum.nextLongElement();  else continue;
				if (longEnum.hasMoreElements()) throughputOut2=longEnum.nextLongElement();  else continue;

	//			throughputOut=hist.elementAt(x+1);
	//			long throughputOut2=hist.elementAt(x+3);

				int throughputHeightOut = (int)((throughputOut)*(clientRect.height)/maxThroughput);
				int throughputHeightOut2 = (int)((throughputOut2)*(clientRect.height)/maxThroughput);

				// Do some clipping - just in case the "MaxThroughput" value wasn't realistic
				if (throughputHeightOut>clientRect.height) throughputHeightOut=clientRect.height;
				if (throughputHeightOut2>clientRect.height) throughputHeightOut2=clientRect.height;

				myGraphics.drawLine(	clientRect.x+x/2,
							clientRect.y+clientRect.height-throughputHeightOut,
							clientRect.x+x/2+1,
							clientRect.y+clientRect.height-throughputHeightOut2);
			}
//		}

		// Paint the footer
		drawFooter(myGraphics, throughputIn2, throughputOut2, LrpStatLook.getControlForeground(), maxThroughput);

		longEnum = null;
		if (ifOpts.drawLegend) drawLegend(myGraphics, clientRect);

		graph.drawImage(offScreenImg,0,0,this);
	}

}