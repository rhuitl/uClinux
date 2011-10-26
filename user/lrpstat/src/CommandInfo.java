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
// $Header: /home/cvs/lrpStat/src/CommandInfo.java,v 1.13 2002/03/12 22:19:12 hejl Exp $

import java.util.Vector;
import java.net.URL;

/**
 * Class that holds information about commands (actions) defined by parameters in the applet
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class CommandInfo {
	public static final int COMMAND_TYPE_GET = 1;
	public static final int COMMAND_TYPE_OPEN = 2;

	public String caption;
	public int commandType;
	public URL commandURL;
	public String commandHost;
	public long commandPort;

}
