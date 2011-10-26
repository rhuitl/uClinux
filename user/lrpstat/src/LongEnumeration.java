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
// $Header: /home/cvs/lrpStat/src/LongEnumeration.java,v 1.7 2002/03/12 22:19:13 hejl Exp $

/**
 * Implements the Enumeration interface for long-values
 * We use a special implementation (rather than a generic Enumeration)
 * te get around having to create and store Long-Objects
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */

public class LongEnumeration implements java.util.Enumeration {

	long[] lElements;
	int nPosition;

	LongEnumeration(int lSize){
		lElements = new long[lSize];
		nPosition = 0;
	}

	public void setElement(int index, long value) {
		lElements[index] = value;
	}

	public void addElement(long value) {
		lElements[nPosition] = value;
		nPosition++;
	}

	public  boolean hasMoreElements() {
		return(nPosition < lElements.length);
	}

	public Object nextElement() {
		nPosition++;
		return((Object)new Long(lElements[nPosition-1]));
	}

	public long nextLongElement() 	 {
		nPosition++;
		return(lElements[nPosition-1]);
	}

	public void rewind() {
		nPosition = 0;
	}

	public long lastLongElement() {
		nPosition = lElements.length-1;
		return(lElements[nPosition]);
	}

	public long previousLongElement() {
		nPosition--;
		return(lElements[nPosition]);
	}

	public  boolean hasPreviousElement() {
		return(nPosition > 0);
	}

}