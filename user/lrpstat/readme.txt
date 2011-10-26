Lrp Network Monitor V0.13beta: Simple network monitor written in Java
Copyright (C) 2001 Martin Hejl linux@hejl.de, http://lrp.hejl.de/

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

Abstract:
lrpStat is a java-applet/application that displays information about network 
devices on a linux router.
This information can be displayed either in plain text, or in graphical format 
(either bar-charts, line-charts or, my favourite, a histogram view).
So, in a way, it's just another network monitor. 

What makes it unique (at least in my opinion) is that it doesn't require much 
software to be installed on the computer to be monitored (aside from a script 
or c-program, some settings in /etc/inetd.conf and /etc/services and of course 
a web-server to serve the applet). But no libs, no X-Server or anything like 
that.

For each monitored device, you can specify any number of "actions". These
actions can be either opening a port to the computer the data is coming from
(and of course, you can specify which port that is) or fetching an URL from
the computer the data is coming from. The actions can be accessed by
right-clicking on the device the actions are defined for (context menu).

For example, you can use this functionality to bring up an ISDN-Device/Modem
and to force it to hang up.

So, if you specify the actions: 
<PARAM NAME=DEV1_ACTION0 VALUE="online;OPEN 60180">
<PARAM NAME=DEV1_ACTION1 VALUE="offline;OPEN 60181">

and your /etc/inetd.conf looks like this:

online  stream tcp nowait root /usr/sbin/tcpd /sbin/isdnctrl dial ippp0
offline stream tcp nowait root /usr/sbin/tcpd /sbin/isdnctrl hangup ippp0

(and "online" and "offline" are specified in /etc/services as ports 60180 and
60181) you can trigger dialing/hangup via the applet/application.

This is great for people like me, who don't trust autodial. Besides, it's fun
to see Microsoft applications desparately trying to connect to some server,
the first time they're run after being installed.


It seems like this works only with 2.2.xx kernels, since the output of 
/proc/net/dev is different with 2.0.xx kernels. If somebody has an idea how to 
get the information about transferred bytes for a specific interface on a 
2.0.xx kernel, please let me know.
