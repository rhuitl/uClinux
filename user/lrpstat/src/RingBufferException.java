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
// $Header: /home/cvs/lrpStat/src/RingBufferException.java,v 1.7 2002/04/10 19:46:22 hejl Exp $

/**
 * Exception for Ringbuffer errors
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */

public class RingBufferException extends java.lang.Exception
{
	RingBufferException() {
		super();
	}

	RingBufferException(String s) {
		super(s);
	}

}