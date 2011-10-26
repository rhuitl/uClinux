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
// $Header: /home/cvs/lrpStat/src/LrpStatModelEvent.java,v 1.14 2002/04/10 19:46:22 hejl Exp $

import java.util.Vector;
import java.util.EventObject;


/**
 * The event that is generated when new data arrives
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class LrpStatModelEvent extends EventObject {

	protected InterfaceOptions ifOpt;
	protected InterfaceInfo ifInfo;

	/**
	 * Creates an empty event object
	 */
	LrpStatModelEvent(Object source) {
		super(source);
		ifOpt=null;
		ifInfo=null;

	}

	/**
	 * Createa an event object with the specified interface informations
	 */
	LrpStatModelEvent(Object source, InterfaceOptions opt, InterfaceInfo info) {
		super(source);
		ifOpt=opt;
		ifInfo=info;
	}

	/**
	 * Returns the interfaceOptions from the event
	 */
	public InterfaceOptions getInterfaceOptions() {
		return(ifOpt);
	}

	/**
	 * Returns the interfaceInfo from the event
	 */
	public InterfaceInfo getInterfaceInfo() {
		return(ifInfo);
	}

}