import java.awt.Color;
import java.awt.image.PixelGrabber;
import java.awt.Image;


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


// $Revision: 1.10 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/LrpStatLook.java,v 1.10 2002/04/10 19:46:22 hejl Exp $

/**
 * Class that keeps info about the desired look
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatLook {


	// The colors used in the applet
	// they're automatically initialized with the default colors
	protected static Color controlBackground 		= new Color(200,200,200);
	protected static Color controlForeground 		=     Color.black;
	protected static Color dataOnlineBackground    	= new Color(20,64,20);
	protected static Color dataTryingBackground    	= new Color(255,255,0);
	protected static Color dataOfflineBackground    = new Color(200,200,200);
	protected static Color dataNoDevBackground    	= new Color(255,255,255);
	protected static Color dataColor1        		=     Color.green;
	protected static Color dataColor2        		=     Color.cyan;
	protected static Color gridColor         		= new Color(0,96,0);
	protected static Color barBackground     		= new Color(40,128,40);
	protected static Color cpuSystem	     		= new Color(0xFF,00,00);
	protected static Color cpuUser		     		= new Color(00,00,0xFF);
	protected static Color cpuNice		     		= new Color(0xFF,0xFF,00);
	protected static Color cpuIdle		     		= controlBackground;
	protected static boolean drawComponentBorder 	= true;
	protected static boolean drawClientBorder    	= true;
	protected static int INSETS                  	= 5;
	protected static String statusFontName    		=  "SansSerif";
	protected static int statusFontSize         	= 10;
	protected static String titleFontName     		= "SansSerif";
	protected static int titleFontSize          	= 12;

	public static Color 	getControlBackground() 		{ return (controlBackground);}
	public static Color 	getControlForeground() 		{ return(controlForeground);}
	public static Color 	getDataOnlineBackground() 	{ return(dataOnlineBackground);}
	public static Color 	getDataTryingBackground() 	{ return(dataTryingBackground);}
	public static Color 	getDataOfflineBackground()	{ return(dataOfflineBackground);}
	public static Color 	getDataNoDevBackground() 	{ return(dataNoDevBackground);}
	public static Color 	getDataColor1() 			{ return(dataColor1);}
	public static Color 	getDataColor2() 			{ return(dataColor2);}
	public static Color 	getGridColor() 				{ return(gridColor);}
	public static Color 	getBarBackground() 			{ return(barBackground);}

	public static Color 	getCpuSystemColor()			{ return(cpuSystem);}
	public static Color 	getCpuUserColor()			{ return(cpuUser);}
	public static Color 	getCpuNiceColor()			{ return(cpuNice);}
	public static Color 	getCpuIdleColor()			{ return(cpuIdle);}

	public static boolean 	getDrawComponentBorder() 	{ return(drawComponentBorder);}
	public static boolean 	getDrawClientBorder() 		{ return(drawClientBorder);}
	public static int 		getINSETS() 				{ return(INSETS);}
	public static String 	getStatusFontName() 		{ return(statusFontName);}
	public static int 		getStatusFontSize() 		{ return(statusFontSize);}
	public static String 	getTitleFontName() 			{ return(titleFontName);}
	public static int 		getTitleFontSize() 			{ return(titleFontSize);}

	public static void 		setControlBackground(Color c) 		{ controlBackground=c;}
	public static void 		setControlForeground(Color c) 		{ controlForeground=c;}
	public static void 		setDataOnlineBackground(Color c) 	{ dataOnlineBackground=c;}
	public static void 		setDataTryingBackground(Color c) 	{ dataTryingBackground=c;}
	public static void 		setDataOfflineBackground(Color c) 	{ dataOfflineBackground=c;}
	public static void 		setDataNoDevBackground(Color c) 	{ dataNoDevBackground=c;}
	public static void 		setDataColor1(Color c) 				{ dataColor1=c;}
	public static void 		setDataColor2(Color c) 				{ dataColor2=c;}
	public static void 		setGridColor(Color c) 				{ gridColor=c;}
	public static void 		setBarBackground(Color c) 			{ barBackground=c;}
	public static void		setCpuSystemColor(Color c)			{ cpuSystem=c;}
	public static void		setCpuUserColor(Color c)			{ cpuUser=c;}
	public static void		setCpuNiceColor(Color c)			{ cpuNice=c;}
	public static void		setCpuIdleColor(Color c)			{ cpuIdle=c;}

	public static void 		setDrawComponentBorder(boolean b) 	{ drawComponentBorder=b;}
	public static void 		setDrawClientBorder(boolean b) 		{ drawClientBorder=b;}
	public static void 		setINSETS(int n) 					{ INSETS=n;}
	public static void 		setStatusFontName(String s) 		{ statusFontName=s;}
	public static void 		setStatusFontSize(int n) 			{ statusFontSize=n;}
	public static void 		setTitleFontName(String s) 			{ titleFontName=s;}
	public static void 		setTitleFontSize(int n) 			{ titleFontSize=n;}



	/**
	 * Takes the Hex-representation of a color
	 * (for example FF0000 for red)
	 * and returns the corresponding color
	 */
	public static Color parseColor(String strColor) {
		try {
			int col = Integer.valueOf(strColor,16).intValue();
			return (new Color(col));
		} catch (NumberFormatException e) {
			System.err.println("Malformed Color " + strColor );
			return (null);
		}
	}


/*


	//============================================================================
	// b r e s l i n e . c
	//
	// VERSION 4: draws from both ends and calculates single offset into FB.
	//            (takes advantage of line symmetry). FIXES MIDPOINT PROBLEM
	//            WHEN DRAWING FROM BOTH ENDS. ALSO MORE EFFICIENT!
	// Programmer:  Kenny Hoff
	// Date:        11/08/95
	// Purpose:     To implement the Bresenham's line drawing algorithm for all
	//              slopes and line directions (using minimal routines).
	//============================================================================

	// EXTERNALLY DEFINED FRAMEBUFFER AND FRAMEBUFFER DIMENSIONS (WIDTH))

	void BresLine(int Ax, int Ay, int Bx, int By, Color col,MemoryImageSource source)
	{

		int intColor = col.getRGB();
	  	int dX, dY, fbXincr, fbYincr, fbXYincr, dPr, dPru, P;

		//------------------------------------------------------------------------
		// STORE THE FRAMEBUFFER ENDPOINT-ADDRESSES (A AND B)
		//------------------------------------------------------------------------
		//  unsigned char far* AfbAddr = &FrameBuffer[Ay*WIDTH+Ax];
		//  unsigned char far* BfbAddr = &FrameBuffer[By*WIDTH+Bx];

		//------------------------------------------------------------------------
		// DETERMINE AMOUNT TO INCREMENT FRAMEBUFFER TO GET TO SUBSEQUENT POINTS
		// (ALSO, STORE THE ABSOLUTE VALUE OF THE CHANGE IN X AND Y FOR THE LINE)
		//------------------------------------------------------------------------
		fbXincr=1;
		if ((dX=Bx-Ax) < 0) {
			dX=-dX;
			fbXincr=-1;
		}


		fbYincr=1;
		if ( (dY=By-Ay) < 0) {
			fbYincr=-1;
			dY=-dY;
		}

		fbXYincr = fbXincr+fbYincr;

		//------------------------------------------------------------------------
		// DETERMINE INDEPENDENT VARIABLE (ONE THAT ALWAYS INCREMENTS BY 1 (OR -1) )
		// AND INITIATE APPROPRIATE LINE DRAWING ROUTINE (BASED ON FIRST OCTANT
		// ALWAYS). THE X AND Y'S MAY BE FLIPPED IF Y IS THE INDEPENDENT VARIABLE.
		//------------------------------------------------------------------------
		if (dY <= dX) {
			dPr = dY+dY;                           // AMOUNT TO INCREMENT DECISION IF RIGHT IS CHOSEN (always)
			P = -dX;                               // DECISION VARIABLE START VALUE
			dPru = P+P;                            // AMOUNT TO INCREMENT DECISION IF UP IS CHOSEN
			dY = dX>>1;                            // COUNTER FOR HALF OF LINE (COMING FROM BOTH ENDS)
			while (true) {
				*AfbAddr=Color;                    // PLOT THE PIXEL FROM END A
				*BfbAddr=Color;                    // PLOT THE PIXEL FROM END B
				if ((P+=dPr) <= 0) {

					AfbAddr+=fbXincr;              // ADVANCE TO NEXT POINT FROM END A
					BfbAddr-=fbXincr;              // ADVANCE TO NEXT POINT FROM END B
					if ((dY=dY-1) <= 0) {
						*AfbAddr=Color;                // (FIX MIDPOINT PROBLEM) PLOT LAST PT FROM END A
						if ((dX & 1) == 0) return;     // FINISHED IF INDEPENDENT IS EVEN (ODD # STEPS)
						*BfbAddr=Color;                // PLOT LAST PT FROM END B IF INDEPENDENT IS ODD (EVEN # STEPS)
						return;
					}
					AfbAddr+=fbXYincr;             // ADVANCE TO NEXT POINT FROM END A
					BfbAddr-=fbXYincr;             // ADVANCE TO NEXT POINT FROM END B
					P+=dPru;                       // INCREMENT DECISION (for up)
					if ((dY=dY-1) <= 0) {
						*AfbAddr=Color;                // (FIX MIDPOINT PROBLEM) PLOT LAST PT FROM END A
						if ((dX & 1) == 0) return;     // FINISHED IF INDEPENDENT IS EVEN (ODD # STEPS)
						*BfbAddr=Color;                // PLOT LAST PT FROM END B IF INDEPENDENT IS ODD (EVEN # STEPS)
						return;
					}
				}
			}
		}

		dPr = dX+dX;
		P = -dY;
		dPru = P+P;
		dX = dY>>1;
		while (true) {
			*AfbAddr=Color;
			*BfbAddr=Color;
			if ((P+=dPr) <= 0) {
				AfbAddr+=fbYincr;
				BfbAddr-=fbYincr;

				if ((dX=dX-1) <= 0) {
					*AfbAddr=Color;
					if ((dY & 1) == 0) return;
					*BfbAddr=Color;
					return;
				}

				AfbAddr+=fbXYincr;
				BfbAddr-=fbXYincr;
				P+=dPru;

				if ((dX=dX-1) <= 0){
					*AfbAddr=Color;
					if ((dY & 1) == 0) return;
					*BfbAddr=Color;
					return;
				}
			}
		}

	}


public static long pixelValue(Image image, int x, int y) {
     // precondition: buffer must not be created from ImageProducer!
     // x,y should be inside the image,
     // Returns an integer representing color value of the x,y pixel.
         int[] pixel=new int[1];
         pixel[0]=0;

     // pixel grabber fills the array with zeros if image you are
     // trying to grab from is non existent (or throws an exception)
         PixelGrabber grabber = new PixelGrabber(image,
                                          x, y, 1, 1, pixel, 0, 0);
         try {
             grabber.grabPixels();
         } catch (Exception e) {System.err.println(e.getMessage());}
         return (long)pixel[0];
     }

*/
}

