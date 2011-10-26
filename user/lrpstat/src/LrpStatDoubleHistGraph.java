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


// $Revision: 1.7 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/LrpStatDoubleHistGraph.java,v 1.7 2002/04/10 19:46:22 hejl Exp $

import java.awt.*;
import java.awt.event.*;

/**
 * Implements a histogram view of the device-data
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatDoubleHistGraph extends LrpStatAbstractGraph  {
//	protected LongRingBuffer hist;

	LrpStatDoubleHistGraph (InterfaceOptions opts) {
		super(opts);
	}


	/**
	 * Paints the grid
	 */
	public void drawGrid(Graphics g, long maxThroughput) {

		g.setColor(LrpStatLook.getGridColor());
		Rectangle clientRect = getClientRect();

		// Don't draw a grid if the device isn't online
		if (isISDNDevice && ISDNStatus != InterfaceInfo.ISDN_ONLINE) {
			Color slightlyDarkerBG = LrpStatLook.getControlBackground();
			g.setColor(new Color(
							slightlyDarkerBG.getRed()-slightlyDarkerBG.getRed()/10,
							slightlyDarkerBG.getGreen()-slightlyDarkerBG.getGreen()/10,
							slightlyDarkerBG.getBlue()-slightlyDarkerBG.getBlue()/10));
		}

		drawTicks(g);

		int gridStep;

		if (ifOpts.gridLineCount == 0 && maxThroughput != 0) {
			// if a maxthroughput was defined, transform the interval to screen coordinates
			gridStep = (int)(((ifOpts.gridInterval)*(clientRect.height/2))/maxThroughput);
		} else {
			if (ifOpts.gridLineCount != 0) {
				// If a linecount was defined
				gridStep = (int)(clientRect.height/2/ifOpts.gridLineCount);
			} else {
				// if neither a linecount nor a maxthroughput were defined, we can't draw a grid
				System.err.println("neither a linecount nor a maxthroughput were defined");
				return;
			}
		}

		// If there would be too many gridlines (because of a silly setting in GRID_INTERVAL), quit here
		if (gridStep < MINIMUM_GRID_STEP ) {
			if(!bModelineErrorDisplayed) {
				bModelineErrorDisplayed=true;
				Debug.println("Grid Interval too small - not drawing grid");
			}
			return;
		}

		// For double histogram view, we need to paint from the _center_ of the control...
		int offset = clientRect.y + clientRect.height/2;
		for (int y=0; y<clientRect.height/2; y+=gridStep) {
			g.drawLine(clientRect.x,offset+y,clientRect.x+clientRect.width-1,offset+y);
			g.drawLine(clientRect.x,offset-y,clientRect.x+clientRect.width-1,offset-y);
		}
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


		if (ifOpts.autoScale) {
			if (!ifOpts.accumulate) maxThroughput = ifOpts.minimumScaleValue;
			if (maxThroughput<hist.max()) {
				nMaxInSize=0;
				nMaxOutSize=0;
				maxThroughput=hist.max();
			}

		} else {
			if (maxThroughput != ifOpts.maxThroughput) {
				nMaxInSize=0;
				nMaxOutSize=0;
				maxThroughput = ifOpts.maxThroughput;
			}
		}

		// Make sure we don't get 0 for maxThroughput
		if (maxThroughput<=ifOpts.minimumScaleValue) maxThroughput = ifOpts.minimumScaleValue;

		// Paint the grid
		if (ifOpts.drawGrid) drawGrid(myGraphics, maxThroughput);

		LongEnumeration longEnum = (LongEnumeration)hist.elements();

		long throughputIn=0;
		long throughputOut=0;

		// Paint the graph
		for (int x=0; longEnum.hasMoreElements(); x+=2) {
			if (longEnum.hasMoreElements()) throughputIn  = longEnum.nextLongElement();  else continue;
			if (longEnum.hasMoreElements()) throughputOut =longEnum.nextLongElement();  else continue;

			int throughputHeightIn = (int)((throughputIn)*(clientRect.height/2)/maxThroughput);
			int throughputHeightOut = (int)((throughputOut)*(clientRect.height/2)/maxThroughput);

			// Do some clipping - just in case the "MaxThroughput" value wasn't realistic
			if (throughputHeightIn>clientRect.height/2) throughputHeightIn=clientRect.height/2;
			if (throughputHeightOut>clientRect.height/2) throughputHeightOut=clientRect.height/2;

			myGraphics.setColor(LrpStatLook.getDataColor1());
			myGraphics.drawLine(clientRect.x+(x/2),
								clientRect.y+clientRect.height/2,
								clientRect.x+(x/2),
								clientRect.y+clientRect.height/2-throughputHeightIn);

			myGraphics.setColor(LrpStatLook.getDataColor2());
			myGraphics.drawLine(clientRect.x+(x/2),
								clientRect.y+clientRect.height/2,
								clientRect.x+(x/2),
								clientRect.y+clientRect.height/2+throughputHeightOut);

		}

		// Paint the footer - throughputIn and throughputOut contains the two newest values
		drawFooter(myGraphics, throughputIn, throughputOut, LrpStatLook.getControlForeground(),maxThroughput);

		if (ifOpts.drawLegend) drawLegend(myGraphics, clientRect);
		graph.drawImage(offScreenImg,0,0,this);
	}

}