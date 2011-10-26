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


// $Revision: 1.8 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/LrpStatApplication.java,v 1.8 2002/04/10 19:46:22 hejl Exp $

import java.awt.*;
import java.awt.event.*;
import java.applet.*;
import java.net.*;
import java.util.*;
import java.io.*;

/**
 * Wrapper class that runs the LrpStatApplet without the need for a browser
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatApplication extends Frame {

	// Vector of applets and the corresponding appletStubs/appletContexts
	protected Vector applets = new Vector();
	protected Vector stubs = new Vector();
	protected boolean verticalAlignment=false;

	// The currently used stub
	protected AppletHandler currentStub;

	// The witdh/height of the frame (can be set by using the command-line parameters
    protected int nFrameWidth=640;
    protected int nFrameHeight=480;

	/**
	 * Called when invoked from the command line
	 */
    public static void main ( String argv[] ) {
		LrpStatApplication f = new LrpStatApplication( argv );
    }

	/**
	 * Creates a new instance of the frame
	 */
    public LrpStatApplication( String argv[] ) {

        super ( "LrpStat" );
        try {
			currentStub = new AppletHandler();
			stubs.addElement((Object)currentStub);
			parseCommandLineParameters( argv );

			// Make sure the frame can be terminated gracefully
			WindowListener l = new WindowAdapter() {
				public void windowClosing(WindowEvent e) {
					for (int i=0; i<applets.size(); i++) {
						Debug.println("Shutting down applet");
						((Applet)(applets.elementAt(i))).stop();
						applets.removeElementAt(i);

					}
					Debug.println("Applet shut down, exiting application");
					System.exit(0);
				}
    		};

			this.addWindowListener(l);

			if (verticalAlignment) {
				setLayout(new GridLayout(stubs.size(),0));
			} else {
				setLayout(new GridLayout(0,stubs.size()));
			}
			setSize( nFrameWidth, nFrameHeight);
			show();

			for (int i=0;i<stubs.size();i++) {
	            Applet applet = (Applet)Class.forName( "LrpStatApplet" ).newInstance();
	            applets.addElement((Object)applet);
				init( applet, (AppletHandler)stubs.elementAt(i) );
			}
//			validate();

			// Start the applets
			for (int i=0; i<applets.size(); i++) {
				((Applet)applets.elementAt(i)).start();
			}


			// Sleep a little to let the controls fully initialise themselves
			try {
				Thread.sleep(100);
			} catch (InterruptedException ie) {}

			// Do a validate again
			validate();



        }
        catch ( Exception e ) {
            e.printStackTrace();
            System.exit( 1 );
        }
    }

	/**
	 * Initializes and starts the applet
	 */
    protected void init( Applet applet, AppletHandler stub ) {
        applet.setStub(stub);
        add(applet);
		applet.init();

    }

	/**
	 * Prints a short help-screen to stdOut
	 */
	 protected void printUsage() {
		System.out.println("LrpStatApplication usage:");
		System.out.println("java LrpStatApplication [-v] ");
		System.out.println("                        [-vertical]");
		System.out.println("                        [-width xx]");
		System.out.println("                        [-height yy]");
		System.out.println("                        -hostname host");
		System.out.println("                        [-configfile filename.html]");
		System.out.println("                        [Appletparameters]");
		System.out.println("");
		System.out.println("-v                print verbose messages");
		System.out.println("-vertical         if more than one host is monitored, use vertical alignment for the controls");
		System.out.println("-configfile:      a html-file that can be used for starting the applet");
		System.out.println("                  in a browser");
		System.out.println("                  The application will parse all parameters and serve them");
		System.out.println("                  to the applet");
		System.out.println("Appletparameters: Any number of pairs or ");
		System.out.println("                  parameterName parameterValue");
		System.out.println("                  This can be used alternatively to specifying a configfile");
		System.out.println("");
		System.out.println("Note: that whole block of -hostname xxx -configfile yyy Appletparameters");
		System.out.println("May be repeated as often as desired (obviously, with different values).");
		System.out.println("This way, you can display several connections to different computers at the same time");
		System.out.println("The applets will be displayed with horizontal alignment (one next to the other)");
		System.out.println("");
		System.out.println("Example:");
		System.out.println("java LrpStatApplication -height 64 -width 96 -hostname router1 -configfile router1.html -hostname router2 -configfile router2.html");
	 }

	/**
	 * Parses the command-line parameters
	 */
    public void parseCommandLineParameters( String argv[]) {
		// Verbose is turned off by default
		Debug.setVerbose(false);


		//if ((argv.length & 1) == 1 || argv[0].equals( "--help" ) || argv[0].equals( "-h" ) || argv[0].equals( "/?" ) || argv[0].equals( "/?" ) ) {
		if (argv[0].equals( "--help" ) || argv[0].equals( "-h" ) || argv[0].equals( "/?" ) || argv[0].equals( "/?" ) ) {
			printUsage();
			System.exit(0);
		}
        for ( int i=0; i<argv.length; i+=2 ) {
            try {
				if ( argv[i].equals( "-vertical" ) ) {
                    verticalAlignment=true;
                    i--;
                }
                else if ( argv[i].equals( "-v" ) ) {
                    Debug.setVerbose(true);
                    i--;
                }
                else if ( argv[i].equals( "-width" ) ) {
                    nFrameWidth = Integer.parseInt( argv[i+1] );
                }
                else if ( argv[i].equals( "-height" ) ) {
                    nFrameHeight = Integer.parseInt( argv[i+1] );
                }
			    else if ( argv[i].equals( "-hostname" ) ) {
					// Check if we have to add a new stub
					if (currentStub.getParameter(argv[i])!=null) {
						currentStub = new AppletHandler();
						stubs.addElement(currentStub);
					}
					currentStub.params.put( argv[i], argv[i+1] );
                }
			    else if ( argv[i].equals( "-configfile" ) ) {
					// Check if we have to add a new stub
					if (currentStub.getParameter(argv[i])!=null) {
						currentStub = new AppletHandler();
						stubs.addElement(currentStub);
					}
					currentStub.params.put( argv[i], argv[i+1] );
					readConfigFile(argv[i+1]);
                }
                else {
					Debug.println("Adding param " + argv[i]  + " with value" + argv[i+1]);
                    currentStub.params.put( argv[i], argv[i+1] );
                }

            }
            catch ( NumberFormatException nfe ) {
                System.err.println("Error: Argument "+argv[i]+ " is not a number." );
            }
        }
    }

	/**
	 * Parser that reads the config-file
	 * This surely needs some more work, but it does the job
	 */
	protected void readConfigFile(String fileName) {
		// Read the file
		BufferedReader configFile;

		try {
			configFile = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)));
		} catch (java.io.FileNotFoundException  ex) {
			System.err.println("File " + fileName + " not found");
			return;
		}

		StringBuffer strContents=new StringBuffer();
		String strLine;
		try {
			while ((strLine = configFile.readLine()) != null ) {
					strContents.append(strLine);
			}

			configFile.close();

		} catch (IOException ioEx) {
			System.err.println("IOException reading " + fileName);
			System.err.println(ioEx);
			return;
		}

		String paramName;
		String paramValue;

		// find all occurrences of "<PARAM ...> tags
		int nStringPos=0;
		strLine = strContents.toString();

		// Find the first tag
		nStringPos=strLine.indexOf("<");
		while (nStringPos != -1) {
			if (strLine.substring(nStringPos, nStringPos+4).equals("<!--")) {
				// Move the pointer to the end of the comment
				nStringPos=strLine.indexOf("->", nStringPos);
				nStringPos=strLine.indexOf("<", nStringPos);
			} else {
				if (strLine.substring(nStringPos, nStringPos+7).toUpperCase().equals("<PARAM ")) {
					nStringPos = strLine.indexOf("NAME", nStringPos);
					paramName = strLine.substring(nStringPos+5, strLine.toUpperCase().indexOf("VALUE", nStringPos)-1);

//					System.err.println("paramName=" + paramName);
					paramName =stripQuotes(paramName );
//					System.err.println("paramName=" + paramName);

					nStringPos = strLine.indexOf("\"", strLine.toUpperCase().indexOf(" VALUE", nStringPos));
					paramValue = strLine.substring(nStringPos+1, strLine.indexOf("\"", nStringPos+1));
					// Move the pointer to the end of the parameter
					nStringPos = strLine.indexOf("\"", nStringPos+1);

					currentStub.params.put( paramName, paramValue );

					Debug.println("Adding Parameter " + paramName + "=" + paramValue);
					// Move the pointer to the end of the tag
					nStringPos = strLine.indexOf(">", nStringPos);
					// Move the pointer to the next tag
					nStringPos=strLine.indexOf("<", nStringPos);
				} else {
					// Move to the next tag
					nStringPos=strLine.indexOf("<", nStringPos+1);
				}
			}
		}

	}

	protected String stripQuotes(String inputValue) {
		String retVal;

		retVal = inputValue.trim();
		while (retVal.startsWith("\"")) {
			retVal = retVal.substring(1);
		}

		while (retVal.endsWith("\"")) {
			retVal = retVal.substring(0,retVal.length()-1);
		}
		return retVal;
	}

	// AppletStub/AppletContext implementation
	protected class AppletHandler implements AppletStub, AppletContext {

		/**
		 * Hashtable that holds the parameters
		 */
		protected Hashtable params = new Hashtable();

		// AppletStub interface --------------------------------------
		/**
		 * Determines if the applet is active
		 */
		public boolean isActive()    {
			return(true);
		}

		/**
		 * Gets the document URL
		 * This is the root-directory of the host to be monitored
		 */
		public URL getDocumentBase() {
			URL url = null;
			try {
				url = new URL( "http://" + getParameter("-hostname") + "/");
			}
			catch ( MalformedURLException ex ) {
				ex.printStackTrace();
			}
			return url;
		}

		/**
		 * Gets the base URL
		 * This is the root-directory of the host to be monitored
		 */
		public final URL getCodeBase() { return getDocumentBase(); }

		/**
		 * Returns the value of the named parameter in the HTML tag
		 */
		public final String getParameter( String name ) {
			return (String)params.get( name );
		}

		/**
		 * Gets a handler to the applet's context
		 */
		public final AppletContext getAppletContext() { return this; }

		/**
		 * Called when the applet wants to be resized
		 */
		public void appletResize( int width, int height ) {

			Insets insets = getInsets();

			setSize( ( width + insets.left + insets.right ),
					( height + insets.top + insets.bottom ) );
			validate();
		}

		// AppletContext interface --------------------------------------
		/**
		 * Returns null
		 */
		public final AudioClip getAudioClip(URL url) {
			return null;
		}

		/**
		 * Returns an Image object that can then be painted on the screen
		 */
		public final Image getImage(URL url) {
			return Toolkit.getDefaultToolkit().getImage( url  );
		}

		/**
		* Returns null
		*/
		public final Applet getApplet(String name) { return null; }

		/**
		 * Returns all applets handled by the frame
		 */
		public final Enumeration getApplets() {
			return applets.elements();
		}

		/**
		 * Dumps the info to stdErr (in debug mode)
		 */
		public void showDocument( URL url ) {
			Debug.println("Applet requested showDocument(" + url + ")");
		}

		/**
		 * Dumps the info to stdErr (in debug mode)
		 */
		public void showDocument( URL url, String target ) {
			Debug.println("Applet requested showDocument(" + url + ", " + target + ")");
		}

		/**
		 * Dumps the info to stdErr (in debug mode)
		 */
		public void showStatus(String text) {
			System.err.println( text );
		}

		public void setStream(java.lang.String s,java.io.InputStream ios) {
		}

		public java.io.InputStream getStream(java.lang.String s) {
			return null;
		}

/* Uncomment the following, if you use JDK 1.4 */
		public Iterator getStreamKeys() {
			return null;
		}

	}
}
