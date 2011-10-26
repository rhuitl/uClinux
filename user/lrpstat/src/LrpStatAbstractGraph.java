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
// $Header: /home/cvs/lrpStat/src/LrpStatAbstractGraph.java,v 1.14 2002/04/10 19:46:22 hejl Exp $

import java.util.Vector;
import java.awt.event.*;
import java.awt.*;
/**
 * Parent class for all views (numeric, bar, line and histogram)
 * Handles common stuff, but doesn't display any data
 *
 * @author       Martin Hejl
 * @version      20020311 0.13beta
 */
public abstract class LrpStatAbstractGraph extends java.awt.Panel implements LrpStatModelListener, ActionListener, ComponentListener {
	protected boolean isISDNDevice=false;
	protected long ISDNStatus=0;
	protected LongRingBuffer hist;
	protected final int MINIMUM_GRID_STEP = 4;
	protected String deviceName;
	protected InterfaceInfo lastValue=null;
	protected InterfaceInfo value=null;
	protected InterfaceInfo offset=null;
	protected int lineHeight=10;
	protected int statusLineHeight =0;
	protected int headerHeight =0;
	protected InterfaceOptions ifOpts;
	protected PopupMenu popup;
	protected Font statusFont=null;
	protected Font titleFont=null;
	protected int nMaxInSize=0;
	protected int nMaxOutSize=0;
	protected Image offScreenImg=null;
	protected Graphics myGraphics=null;
	protected long maxThroughput = 0;
	protected boolean bModelineErrorDisplayed=false;
	protected LrpStatAction action;
	protected Rectangle _clientRect = new Rectangle(0,0,0,0);
	protected boolean rectDirty = true;
	protected int nInLength=0;
	protected int nOutLength=0;
	private long lUser=-1;
	private long lSystem=-1;
	private long lIdle=-1;
	private long lNice=-1;

	private long lUser_prev=-1;
	private long lSystem_prev=-1;
	private long lIdle_prev=-1;
	private long lNice_prev=-1;
	protected int pixels[];
//	protected MemoryImageSource source;
	private int tickStart=0;


//	private boolean bMouseOverTitle=false;
	private Rectangle titleRect = null;

	/**
	 * Initializes the internal data and the popup-menu
	 */
	LrpStatAbstractGraph(InterfaceOptions opts) {
		// Register a component-listener, so we get informed when the
		// component is resized
		addComponentListener(this);

		deviceName = opts.deviceLabel;
		ifOpts = opts;

		tickStart=ifOpts.tickInterval;

		// If there are actions defined, add a menu with these actions
		if (ifOpts.actions.size()>0) {

			// Create a popup menu
			popup = new PopupMenu("Actions");


			MenuItem item;
			CommandInfo cmd;
			// Add the specified actions to the popup menu
			for (int i=0; i<ifOpts.actions.size(); i++){
				cmd = (CommandInfo)ifOpts.actions.elementAt(i);
				item = new MenuItem(cmd.caption);
				item.setActionCommand(String.valueOf(i));
				item.addActionListener(this);
				Debug.println("Adding menu item " + cmd.caption);
				popup.add(item);
			}
			// Add the popup menu to this component

			add(popup);

			enableEvents(AWTEvent.MOUSE_EVENT_MASK+AWTEvent.MOUSE_MOTION_EVENT_MASK);


		}

		// Create an instance of Interface info with the specified offset values
		offset = new InterfaceInfo(	"", "", opts.inOffset, 0,0,0,0,0,0,0,ifOpts.outOffset,0,0,0,0,0,0,0, false, 0, 0);

		if (!ifOpts.drawTitle) {
			if (headerHeight!=0) {
				headerHeight=0;  //else headerHeight += LrpStatLook.getINSETS();
			}
		}
		if (!ifOpts.drawStatus) {
			if (statusLineHeight!=0) {
				statusLineHeight=0; //else statusLineHeight += LrpStatLook.getINSETS();
			}
		}
		rectDirty = true;

	}

	/**
	 * Returns a new Instance where the values are the difference of v1 and v2
	 */
	public InterfaceInfo subtract(InterfaceInfo v1, InterfaceInfo v2) {
		return(new InterfaceInfo(
			v1.getName(),
			v1.getStatus(),
			v1.getBytes(InterfaceInfo.DIRECTION_RECEIVE) - v2.getBytes(InterfaceInfo.DIRECTION_RECEIVE),
			v1.getPackets(InterfaceInfo.DIRECTION_RECEIVE) - v2.getPackets(InterfaceInfo.DIRECTION_RECEIVE),
			v1.getErrors(InterfaceInfo.DIRECTION_RECEIVE) - v2.getErrors(InterfaceInfo.DIRECTION_RECEIVE),
			v1.getDrop(InterfaceInfo.DIRECTION_RECEIVE) - v2.getDrop(InterfaceInfo.DIRECTION_RECEIVE),
			v1.getFifo(InterfaceInfo.DIRECTION_RECEIVE) - v2.getFifo(InterfaceInfo.DIRECTION_RECEIVE),
			v1.getFrame(InterfaceInfo.DIRECTION_RECEIVE) - v2.getFrame(InterfaceInfo.DIRECTION_RECEIVE),
			v1.getCompressed(InterfaceInfo.DIRECTION_RECEIVE) - v2.getCompressed(InterfaceInfo.DIRECTION_RECEIVE),
			v1.getMulticast(InterfaceInfo.DIRECTION_RECEIVE) - v2.getMulticast(InterfaceInfo.DIRECTION_RECEIVE),

			v1.getBytes(InterfaceInfo.DIRECTION_TRANSMIT) - v2.getBytes(InterfaceInfo.DIRECTION_TRANSMIT),
			v1.getPackets(InterfaceInfo.DIRECTION_TRANSMIT) - v2.getPackets(InterfaceInfo.DIRECTION_TRANSMIT),
			v1.getErrors(InterfaceInfo.DIRECTION_TRANSMIT) - v2.getErrors(InterfaceInfo.DIRECTION_TRANSMIT),
			v1.getDrop(InterfaceInfo.DIRECTION_TRANSMIT) - v2.getDrop(InterfaceInfo.DIRECTION_TRANSMIT),
			v1.getFifo(InterfaceInfo.DIRECTION_TRANSMIT) - v2.getFifo(InterfaceInfo.DIRECTION_TRANSMIT),
			v1.getCompressed(InterfaceInfo.DIRECTION_TRANSMIT) - v2.getCompressed(InterfaceInfo.DIRECTION_TRANSMIT),
			v1.getColls(InterfaceInfo.DIRECTION_TRANSMIT) - v2.getMulticast(InterfaceInfo.DIRECTION_TRANSMIT),
			v1.getCarrier(InterfaceInfo.DIRECTION_TRANSMIT) - v2.getCarrier(InterfaceInfo.DIRECTION_TRANSMIT),
			v1.getISDNDevice(),
			v1.getISDNStatus(),
			v1.getTimestamp() - v2.getTimestamp()

		));

	}

	/**
	 * Called by the model when new data arrives
 	 */
	public void dataArrived(LrpStatModelEvent e) {
		value = e.getInterfaceInfo();


		Rectangle clientRect=getClientRect();
		if (hist == null) {
			hist = new LongRingBuffer(2+2*clientRect.width);
		}

		if (lastValue==null) lastValue=value;

		// If reveived a null value, we can stop here
		if (value == null){
			repaint();
			return;
		}

		isISDNDevice = value.getISDNDevice();
		ISDNStatus   = value.getISDNStatus();

		/* Fetch CPU-Info */
		setCPUUsage(value.getSystem(), value.getUser(), value.getNice(), value.getIdle());

		// Caluculate the troughput values and save it in the vector
		long throughputIn=value.getBytes(InterfaceInfo.DIRECTION_RECEIVE);
		long throughputOut=value.getBytes(InterfaceInfo.DIRECTION_TRANSMIT);

		if (!ifOpts.absoluteValue) {
			throughputIn-=lastValue.getBytes(InterfaceInfo.DIRECTION_RECEIVE);;
			throughputOut-=lastValue.getBytes(InterfaceInfo.DIRECTION_TRANSMIT);;

			if (ifOpts.percentValue) {
				throughputIn=getInPercent(throughputIn, throughputIn+throughputOut);

				//throughputOut=0; //throughputOut=100-throughputIn;
				// now check if there is a second value
				// could be, if there's more than one cpu
				// if not, we'll get all 0s, so no harm is done
				long tmpThroughputIn=value.getPackets(InterfaceInfo.DIRECTION_RECEIVE);
				long tmpThroughputOut=value.getPackets(InterfaceInfo.DIRECTION_TRANSMIT);

				//Debug.println("In2: " + tmpThroughputIn + " Out2: " + tmpThroughputOut);
				tmpThroughputIn-=lastValue.getPackets(InterfaceInfo.DIRECTION_RECEIVE);;
				tmpThroughputOut-=lastValue.getPackets(InterfaceInfo.DIRECTION_TRANSMIT);;

				//Debug.println("In2: " + tmpThroughputIn + " Out2: " + tmpThroughputOut);
				throughputOut=getInPercent(tmpThroughputIn, tmpThroughputIn+tmpThroughputOut);
			}
		}



		throughputIn-=offset.getBytes(InterfaceInfo.DIRECTION_RECEIVE);
		if (throughputIn<0) throughputIn = 0;

		throughputOut-=offset.getBytes(InterfaceInfo.DIRECTION_TRANSMIT);
		if (throughputOut<0) throughputOut=0;


		if (!ifOpts.dontNormalize && !ifOpts.percentValue) {
			// Normalize to Throughput per second
			long lTimeDiff = (value.getTimestamp() - lastValue.getTimestamp()) ;

			// Make sure we don't get a Div by zero
			if (lTimeDiff==0) lTimeDiff=1;

			throughputIn = (throughputIn * 1000) / lTimeDiff;
			throughputOut = (throughputOut * 1000) / lTimeDiff;
		}


		hist.push(throughputIn);
		hist.push(throughputOut);

		// get rid of entries that have scrolled out of the window
		boolean scrolling=false;
		while (hist.getElementCount() > 2*clientRect.width+2) {
			// Kick the oldest entries
			try {
				hist.pop();
				hist.pop();
			} catch (RingBufferException ex) {}
			scrolling = true;
		}
		lastValue=value;

		if (scrolling)	{
			tickStart--;
			if (tickStart <= 0) tickStart=ifOpts.tickInterval;
		}


		// Force a repaint
		repaint();
	}


	/**
	 * Returns a rectangle with the bounds of the area where the data can be displayed
	 */
	protected Rectangle getClientRect() {
		//System.err.println("INSETS=" + LrpStatLook.getINSETS)();

		if (rectDirty) {
			_clientRect.x = LrpStatLook.getINSETS();
			_clientRect.y = LrpStatLook.getINSETS()+headerHeight;
			_clientRect.width = getSize().width - 2*LrpStatLook.getINSETS();
			_clientRect.height = getSize().height-2*LrpStatLook.getINSETS()-headerHeight-statusLineHeight;

			if (_clientRect.height<0) _clientRect.height=0;
			if (_clientRect.width<0)  _clientRect.width=0;

			rectDirty = false;
		}

		return (_clientRect);
	}

	/**
	 *  Draws the header (title of the interface)
	 */
	public void drawHeader(Graphics g, String title, Color foreground) {
		if (!ifOpts.drawTitle) return;

		Font oldFont=g.getFont();

		g.setFont(titleFont);

		FontMetrics fm;
		fm = g.getFontMetrics();

		Rectangle clientRect = getClientRect();



		// Draw the title if it fits into the window
		if ((LrpStatLook.getINSETS() + fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent()) < getSize().height)  {
			if (titleRect == null) {
				titleRect = new Rectangle(LrpStatLook.getINSETS()-1,LrpStatLook.getINSETS()-1, fm.stringWidth(title)+2, headerHeight-2 );
			}

			g.setColor(foreground);
			g.drawString(title, LrpStatLook.getINSETS(), LrpStatLook.getINSETS() + lineHeight);

			g.setColor(LrpStatLook.getControlBackground().brighter());
/*			if (bMouseOverTitle) {
				g.draw3DRect(titleRect.x, titleRect.y, titleRect.width, titleRect.height, false);
			}*/

		}

		g.setFont(oldFont);


	}


	protected void drawCPUUsage(Graphics g, Rectangle clientRect) {

		if (ifOpts.displayCPUUsage != true) return;
//		if (LrpStatLook.getINSETS()<4) return;

		Color previousColor=g.getColor();

		int sys  = (int)(getSystemPercent() * clientRect.width / 100);
		int nice = (int)(getNicePercent()   * clientRect.width / 100);
		int user = (int)(getUserPercent()   * clientRect.width / 100);
		int idle = (int)(getIdlePercent()   * clientRect.width / 100);




		int yStart = 2;
		int insets = LrpStatLook.getINSETS();

		if (insets <=2) {
			yStart = 0;
			insets = 4;
		}
		//Debug.println("Drawing cpu at " + insets + "/" + yStart + " " + (insets+sys+user+nice) + "/" + (insets-2));

		//Debug.println(yStart + ":" + sys + "/" + user + "/" + nice + "/" + idle);
		g.setColor(LrpStatLook.getCpuIdleColor());
		if (idle>0) g.fillRect( insets+sys+user+nice,
								yStart ,
								idle,
								insets-2);

		g.setColor(LrpStatLook.getCpuNiceColor());
		if (nice>0) g.fillRect( insets+sys+user,
								yStart,
								nice,
								insets-2);

		g.setColor(LrpStatLook.getCpuUserColor());
		if (user>0) g.fillRect( insets+sys,
								yStart,
								user,
								insets-2);

		g.setColor(LrpStatLook.getCpuSystemColor());
		if (sys>0) g.fillRect( 	insets,
								yStart,
								sys,
								insets-2);


		g.setColor(previousColor);
	}

	/**
	 * Draws the footer (in-value, out-value and maximum value)
	 */
	public void drawFooter(Graphics g, long in, long out, Color foreground, long maxThroughput) {

		if (!ifOpts.drawStatus) return;

		Font oldFont=g.getFont();

		g.setFont(statusFont);

		FontMetrics fm;
		fm = g.getFontMetrics();

		// Find out how long the InValue+label is
		if (nMaxInSize==0){
			String s;
			s = ifOpts.inCaption + ": " + maxThroughput + " ";
			nMaxInSize = fm.stringWidth(s);
		}
		// Find out how long the OutValue+label is
		if (nMaxOutSize==0){
			String s;
			s = ifOpts.outCaption + ": " + maxThroughput;
			nMaxOutSize = fm.stringWidth(s);
		}

		// Find out how long the MaxValue+label is
		int nMaxThroughputSize;
		if (ifOpts.autoScale) {
			String s;
			s = " Max:" + maxThroughput;
			nMaxThroughputSize = fm.stringWidth(s);
		} else {
			nMaxThroughputSize =0;
		}

		Rectangle clientRect = getClientRect();

		// Paint the labels, if they all fit into the control
		g.setColor(foreground);
		if (getSize().height -  (fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent()) > clientRect.y + clientRect.height
		  && nMaxInSize+nMaxOutSize+nMaxThroughputSize < clientRect.width) {
			int yPos;
			int diff = (fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent());

			yPos = clientRect.y+clientRect.height+diff;
			yPos += ((getSize().height - yPos)/2);


			String s;
			long val;
			val = in ;
			s = ifOpts.inCaption + ": " + Long.toString(val);
			g.drawString(s, clientRect.x, yPos);

			val = out;
			s = ifOpts.outCaption + ": " + Long.toString(val);
			g.drawString(s, clientRect.x + nMaxInSize, yPos);

			if (ifOpts.autoScale) {
				s = " Max:" + maxThroughput;
				g.drawString(s, clientRect.x + nMaxInSize + nMaxOutSize, yPos);
			}
		}

		g.setFont(oldFont);
	}


	/**
	 * Paints the grid
	 */
	public void drawGrid(Graphics g, long maxThroughput) {
		int gridStep=0;

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

		if (ifOpts.gridLineCount == 0 && maxThroughput != 0) {
			// if a maxthroughput was defined, transform the interval to screen coordinates
			gridStep = (int)(((ifOpts.gridInterval)*(clientRect.height))/maxThroughput);
		} else {
			if (ifOpts.gridLineCount != 0) {
				// If a linecount was defined
				gridStep = (int)(clientRect.height/ifOpts.gridLineCount);
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
		for (int y=clientRect.y+clientRect.height; y>clientRect.y; y-=gridStep) {
			g.drawLine(clientRect.x,y,clientRect.x+clientRect.width-1,y);
			//for (int x=clientRect.x; x <clientRect.x+clientRect.width; x+=2) {
			//	g.drawLine(x,y,x,y);
			//}
		}
	}

	// Draw a legend in the colors of "in" and "out"
	public void drawLegend(Graphics g, Rectangle clientRect) {
		//Debug.println("into drawLegend");
		if (isISDNDevice && ISDNStatus != InterfaceInfo.ISDN_ONLINE) {

			return;
		}

		Font oldFont=g.getFont();

		g.setFont(statusFont);

		FontMetrics fm;
		fm = g.getFontMetrics();

		String strIn = ifOpts.inCaption + " ";
		if (nInLength==0){
			nInLength = fm.stringWidth(strIn);
		}

		String strOut = ifOpts.outCaption;
		if (nOutLength==0){
			nOutLength = fm.stringWidth(strOut);
		}
		String strInOut = strIn + strOut;

		int xPos=clientRect.x + clientRect.width - LrpStatLook.getINSETS() - nInLength - nOutLength;
		int yPos=clientRect.y + lineHeight+2;

		// Clip the Legend if necessary
		if (yPos> clientRect.y + clientRect.height) return;

		// Clear the background around the legend

		setBackgroundColor(g);
		//g.setColor(LrpStatLook.getDataBackground());
		g.drawString(strInOut, xPos-1, yPos-1);
		g.drawString(strInOut, xPos-1, yPos);
		g.drawString(strInOut, xPos-1, yPos+1);
		g.drawString(strInOut, xPos, yPos+1);
		g.drawString(strInOut, xPos, yPos-1);
		g.drawString(strInOut, xPos+1, yPos-1);
		g.drawString(strInOut, xPos+1, yPos);
		g.drawString(strInOut, xPos+1, yPos+1);

		// Draw the legend for "in"
		g.setColor(LrpStatLook.getDataColor1());
		g.drawString(	strIn,
						xPos,
						yPos);

		// Clear the background around the legend
		xPos = clientRect.x + clientRect.width - LrpStatLook.getINSETS() - nOutLength;
		yPos = clientRect.y + lineHeight+2;

		// Draw the legend for "out"
		g.setColor(LrpStatLook.getDataColor2());
		g.drawString(	strOut,
						xPos,
						yPos);

		g.setFont(oldFont);
	}

	/**
	 *  Draws ticks for everx tickInterval pixels along the x-axis
	 */
	public void drawTicks(Graphics g) {
		if (!ifOpts.drawTicks) return;

		// We rely on the calling function (drawGrid) to set the color

		/* if there's no border, we can't draw any ticks
		  (since they'll be drawn _below_ the border
		*/

		/* get tickInterval */

		/* paint them */
		Rectangle clientRect = getClientRect();

		for (int xPos = clientRect.x+tickStart; xPos<clientRect.x+clientRect.width;xPos+=ifOpts.tickInterval) {
			g.drawLine(xPos, clientRect.y, xPos, clientRect.y+clientRect.height);
		//	g.drawLine(clientRect.x,y,clientRect.x+clientRect.width-1,y);
		}

		/* draw the legend, if possible (and requested) */
	}

	/**
	 *  Does the painting that's common to all controls
	 */
	public void paint(Graphics graph) {
		FontMetrics fm;


		if (myGraphics == null) {
			int width = getSize().width;
			int height = getSize().height;
//			pixels = new int[width*height];
//			source = new MemoryImageSource(width, height, pixels, 0, width);
//			source.setAnimated(true);
			offScreenImg = createImage(width,height);

			myGraphics = offScreenImg.getGraphics();
		}

		// Set the font to be used
		Font oldFont=myGraphics.getFont();

		if (statusFont==null) {
			statusFont = new Font(LrpStatLook.getStatusFontName(), 0 , LrpStatLook.getStatusFontSize());
		}

		if (titleFont==null) {
			titleFont = new Font(LrpStatLook.getTitleFontName(), 0 , LrpStatLook.getTitleFontSize());
		}

		myGraphics.setFont(statusFont);
		fm = myGraphics.getFontMetrics();
		if (ifOpts.drawStatus) {
			// Make sure that changes to this value are reflected in the clientRect
			if (statusLineHeight != fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent()+ LrpStatLook.getINSETS()) {
				statusLineHeight = fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent()+ LrpStatLook.getINSETS();
				rectDirty = true;
			}


		}

		myGraphics.setFont(titleFont);
		fm = myGraphics.getFontMetrics();

		lineHeight = fm.getLeading() + fm.getMaxAscent() + fm.getMaxDescent();

		if (ifOpts.drawTitle) {
			// Make sure that changes to this value are reflected in the clientRect
			if (headerHeight !=  lineHeight + LrpStatLook.getINSETS()) {
				headerHeight =  lineHeight + LrpStatLook.getINSETS();
				rectDirty = true;
			}
		}


		Rectangle clientRect = getClientRect();

		// Draw the background
		myGraphics.setColor(LrpStatLook.getControlBackground());

		myGraphics.fillRect(0,0, getSize().width,getSize().height);
		if (LrpStatLook.getDrawComponentBorder()) {
			myGraphics.draw3DRect(1,1, getSize().width-2,getSize().height-2, true);
		}


		// Draw the inner border and fill the interior
		// Ok, I finally got why I always seemed to get "empty" areas (areas that would not be filled)

		// From the API-Reference:
		// Coordinates are infinitely thin and lie between the pixels of the output device. Operations which draw the outline of a
		// figure operate by traversing an infinitely thin path between pixels with a pixel-sized pen that hangs down and to the right
		// of the anchor point on the path. Operations which fill a figure operate by filling the interior of that infinitely thin path.

		// So, in short the outer bounds of fillRect(x,y,w,h) and drawRect(x,y,w,h) are different!!!

		if (LrpStatLook.getDrawClientBorder()) {
			myGraphics.draw3DRect(clientRect.x-1,
				clientRect.y-1,
				clientRect.width+2,
				clientRect.height+2,
				false);
		}


		setBackgroundColor(myGraphics);

		myGraphics.fillRect(clientRect.x , clientRect.y,clientRect.width+1, clientRect.height+1);
		drawHeader(myGraphics, deviceName, LrpStatLook.getControlForeground());

		drawCPUUsage(graph, clientRect);

		myGraphics.setFont(oldFont);

		graph.drawImage(offScreenImg,0,0,this);

	}

	public void setBackgroundColor(Graphics g) {
		if (value!=null) {
			if (isISDNDevice) {
				switch (value.getISDNStatus()) {
					case InterfaceInfo.ISDN_OFFLINE: 	g.setColor(LrpStatLook.getDataOfflineBackground());
														break;
					case InterfaceInfo.ISDN_ONLINE: 	g.setColor(LrpStatLook.getDataOnlineBackground());
														break;
					case InterfaceInfo.ISDN_TRYING: 	g.setColor(LrpStatLook.getDataTryingBackground());
														break;

				}

			} else g.setColor(LrpStatLook.getDataOnlineBackground());
		} else g.setColor(LrpStatLook.getDataNoDevBackground());
	}

	// Don't clear the background on an uptate - this is done in paint of the implementing classes
	public void update(Graphics g) {
		paint(g);
	}

	/**
	* Returns true if the specified coordinates are _within_ the title rectangle
	* (the border doesn't count
	*/
	private boolean hitTest(long x, long y, Rectangle r) {
		if (r==null) return(false);
		return (	x>r.x && y>r.y && x<r.x+r.width && y<r.y+r.height);
	}

	/**
	 * Called when a mouse-event occurs
	 */
	public void processMouseEvent(MouseEvent e) {
		/**
		 * If the mouse-event was a popup-trigger (this is different on different plattforms)
		 * show the popup
		 */
		//Debug.println("PopupTrigger:" + e.isPopupTrigger() + " X:" + e.getX() + " Y" +  e.getY() + " ClientRect:" +  getClientRect() + " hitTest:" + hitTest(e.getX(), e.getY(), getClientRect()));
		if (e.isPopupTrigger() && hitTest(e.getX(), e.getY(), getClientRect())) {
			action = new LrpStatAction();

			// Make sure the VM doesn't wait for an action thread that's blocked
			action.setDaemon(true);

			action.setPopup(popup, e.getComponent(), e.getX(), e.getY());

			action.start();
		}


/*		// did the state change?
		if (bMouseOverTitle!=oldValue) {
			// draw the Menu border
			repaint();
		}*/


		if (hitTest(e.getX(), e.getY(), titleRect) && (e.getID()==MouseEvent.MOUSE_PRESSED && (e.getModifiers() & MouseEvent.BUTTON1_MASK)!=0) ){
			action = new LrpStatAction();

			// Make sure the VM doesn't wait for an action thread that's blocked
			action.setDaemon(true);
			action.setPopup(popup, e.getComponent(), titleRect.x, titleRect.y+titleRect.height+1);
			action.start();

		}

		super.processMouseEvent(e);
	}

	/*protected void processMouseMotionEvent(MouseEvent e) {

		boolean oldValue = bMouseOverTitle;
		if (e.getID() == MouseEvent.MOUSE_MOVED) {

			bMouseOverTitle = hitTest(e.getX(), e.getY(), titleRect);

			// did the state change?
//			if (bMouseOverTitle!=oldValue) {
//				// draw the Menu border
//				repaint();
//			}

		}
	}*/
	/**
	 * Part of the actionListener interface
	 * Called, when the user selects an item from the popup menu
	 */
 	public void	actionPerformed(ActionEvent e) 	{
		int index;

		// Extract the number from the action event (to make things easier,
		// the actionCommand is the index of the command in the actions-Vector
		try {
			index = Integer.parseInt(e.getActionCommand());
			if (index>=0 && index<ifOpts.actions.size()) {

				action = new LrpStatAction();

				// Make sure the VM doesn't wait for an action thread that's blocked
				action.setDaemon(true);

				action.setCommand((CommandInfo)ifOpts.actions.elementAt(index));
				action.start();
			}
		} catch (NumberFormatException ex) {return;}
	}



	// Part of the componentListener interface
	public void componentHidden(ComponentEvent e)  {
		// Nothing to be done here
	}

	// Part of the componentListener interface
	public void componentMoved(ComponentEvent e) {
		// Nothing to be done here
	}

	// Part of the componentListener interface
	// Called when the component gets resized
	public void componentResized(ComponentEvent e) {
		// Get rid of the old offlineImage and offlineGraphics
		// since they don't have the right dimensions anymore
		// The implementing classes will create a new offscreen-image and -graphics
		// the next time their paint routine is called
			if (offScreenImg != null) {
				offScreenImg.flush();
			}

			offScreenImg = null;
			myGraphics = null;

			rectDirty = true;

			repaint();

	}

	// Part of the componentListener interface
	public void componentShown(ComponentEvent e) {
		// Nothing to be done here
	}

	public Dimension getPreferredSize()	{
		return(new Dimension(20,200));
	}

	public Dimension getMinimumSize()	{
		return(new Dimension(10,500));
	}

	protected void setCPUUsage(long lSys, long lUsr, long lN, long lI) {
		long t;

		//Debug.println("data arrived" + "," + lSys + "," + lUsr + "," + lN + "," + lI );
		t = (lSys + lUsr + lN + lI) - (lSystem + lUser + lNice + lIdle);

		if (lSystem==-1 ||lUser==-1||lNice==-1||lIdle==-1) {

			lSystem = lSys;
			lUser = lUsr;
			lNice = lN;
			lIdle = lI;

			lSystem_prev = lSys;
			lUser_prev = lUsr;
			lNice_prev = lN;
			lIdle_prev = lI;
		}
		else
		{
			lSystem_prev = lSystem;
			lUser_prev 	= lUser;
			lNice_prev 	= lNice;;
			lIdle_prev = lIdle;;


			lSystem = lSys;
			lUser = lUsr;
			lNice = lN;
			lIdle = lI;

		}

	}

	protected long getInPercent(long currentValue, long totalValue) {
		// If total is 0, we set the percentage to 0 percent
		if (totalValue==0) {
			return(0);
		} else {
			return((100*currentValue)/totalValue);
		}
	}

	protected long getSystemPercent(){
		long t = (lSystem + lUser + lNice + lIdle) - (lSystem_prev + lUser_prev + lNice_prev + lIdle_prev);
		if (t==0) t=1;
		return(100*(lSystem-lSystem_prev))/t;
	}

	protected long getUserPercent(){
		long t = (lSystem + lUser + lNice + lIdle) - (lSystem_prev + lUser_prev + lNice_prev + lIdle_prev);
		if (t==0) t=1;
		return(100*(lUser-lUser_prev))/t;

	}

	protected long getNicePercent(){
		long t = (lSystem + lUser + lNice + lIdle) - (lSystem_prev + lUser_prev + lNice_prev + lIdle_prev);
		if (t==0) t=1;
		return(100*(lNice-lNice_prev))/t;
	}

	protected long getIdlePercent(){
		long t = (lSystem + lUser + lNice + lIdle) - (lSystem_prev + lUser_prev + lNice_prev + lIdle_prev);
		if (t==0) t=1;
		return(100*(lIdle-lIdle_prev))/t;
	}

}
