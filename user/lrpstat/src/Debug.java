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
// $Header: /home/cvs/lrpStat/src/Debug.java,v 1.6 2002/03/12 22:19:12 hejl Exp $

/**
 * Debug-Class that encapsulates debug-output
 * by setting DEBUG=false, all debugging output will be
 * turned off
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class Debug {
	protected static boolean DEBUG = true;

	public static void setVerbose(boolean b) {
		DEBUG=b;
	}
	public static void println(String s) {
		if (DEBUG) System.err.println(s);
	}

	public static void print(String s) {
		if (DEBUG) System.err.print(s);
	}

}