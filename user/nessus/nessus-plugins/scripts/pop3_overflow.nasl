#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      This one script can and does test for numerous BugIDs and CVEs.  Added reference
#           links to all posted vulnerabilities with boundary lengths less than 
#           the currrent script value of 2048.  
#           All of these posted in the Bugtraq Database appear vulnerable (not tested).
#           Links are current up to 11/16/2002
#
# See the Nessus Scripts License for details
#
# 
#

if(description)
{
 script_id(10184);
 script_bugtraq_id(2781, 2811, 4055, 4295, 4614, 4789, 790, 830, 894, 942);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2002-0799", "CVE-1999-0822");
 
 name["english"] = "Various pop3 overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote POP3 server might be vulnerable to a buffer overflow 
bug when it is issued at least one of these commands, with a too long 
argument :

	auth
	user
	pass

If confirmed, this problem might allow an attacker to execute
arbitrary code on the remote system, thus giving him an interactive
session on this host.

Solution : If you do not use POP3, disable this service in /etc/inetd.conf
and restart the inetd process. Otherwise, upgrade to a newer version.

See also : http://online.securityfocus.com/archive/1/27197
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to overflow the in.pop3d buffers";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "qpopper.nasl");
 script_exclude_keys("pop3/false_pop3");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

fake = get_kb_item("pop3/false_pop3");
if(fake)exit(0);
port = get_kb_item("Services/pop3");
if(!port)port = 110;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  d = recv_line(socket:soc, length:1024);
  if (!d || d !~ '^\\+OK') { close(soc); exit(0); }	# Not a POP3 server
  if ( egrep(pattern:"Qpopper.*4", string:d) ) exit(0);

  c = string("AUTH ", crap(2048), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  if(!d)security_hole(port);
  else {
  	c = string("USER ", crap(1024), "\r\n");
	send(socket:soc, data:c);
	d = recv_line(socket:soc, length:1024);
	if(!d)security_hole(port);
	else
	{
	 c = string("PASS ", crap(1024), "\r\n");
	 send(socket:soc, data:c);
	 d = recv_line(socket:soc, length:1024);
	 if(!d)security_hole(port);
	}
       }
   close(soc);
  }
 }
