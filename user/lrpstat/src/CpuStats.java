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

// $Revision: 1.5 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/CpuStats.java,v 1.5 2002/03/12 22:19:12 hejl Exp $

/**
 * Class that holds the CPU-Info
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */
public class CpuStats
{
	protected long lUser;
	protected long lSystem;
	protected long lNice;
	protected long lIdle;

	public CpuStats() {
		lUser=0;
		lSystem=0;
		lNice=0;
		lIdle=100;
	}

	public void setUser(long l) {
		lUser = l;
	}

	public long getUser() {
		return(lUser);
	}


	public void setSystem(long l) {

		lSystem = l;
	}

	public long getSystem() {
		return(lSystem);
	}



	public void setNice(long l) {
		lNice = l;
	}

	public long getNice() {
		return(lNice);
	}


	public void setIdle(long l) {
		lIdle = l;
	}

	public long getIdle() {
		return(lIdle);
	}


	public long getTotal() {
		long l;

		l = lUser + lSystem + lNice + lIdle;

		if (l<=0) l = 1;

		return(l);
	}


}
