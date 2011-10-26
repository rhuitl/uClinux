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

// $Revision: 1.6 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/LrpStatAction.java,v 1.6 2002/03/12 22:19:13 hejl Exp $

import java.io.BufferedInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.net.Socket;
import java.awt.*;

/**
 * Class that executes the specified Action in it's own thread
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatAction extends java.lang.Thread {

	protected CommandInfo cmd=null;
	protected PopupMenu popup;
	protected Component popupComponent = null;
	protected int popupX=0;
	protected int popupY=0;


	public void setPopup(java.awt.PopupMenu p, java.awt.Component c, int x, int y) {
		popup = p;
		popupX=x;
		popupY=y;
		popupComponent = c;

	}

	public void setCommand(CommandInfo c) {
		cmd = c;
	}
	/**
	 * Executes the specified command
	 */
	public void run() {
		if (popup!=null) {
			popup.show(popupComponent, popupX, popupY);
			popup=null;
			return;
		}


		if (cmd == null) return;

		switch (cmd.commandType) {
			// Open an UrlConnection
			case CommandInfo.COMMAND_TYPE_GET:
				try {
					cmd.commandURL.openConnection();

					BufferedReader in = new BufferedReader(new InputStreamReader(cmd.commandURL.openStream()));
					String strLine;
					Debug.println("Server responded:");
					while ((strLine = in.readLine()) != null) {
						Debug.println(strLine);
					}
					in.close();
				} catch (IOException e) {}
				break;
			// Open a port
			case CommandInfo.COMMAND_TYPE_OPEN:
				try {
					Socket sockServerConnection = new Socket(cmd.commandHost, (int)cmd.commandPort);
					BufferedReader in = new BufferedReader(new InputStreamReader(sockServerConnection.getInputStream()));
					String strLine;
					Debug.println("Server responded:");
					while ((strLine = in.readLine()) != null) {
						Debug.println(strLine);
					}
					in.close();
					sockServerConnection.close();
				} catch (IOException e) {}
				break;
		}
		cmd = null;
		Debug.println("Action terminated");
	}


}

