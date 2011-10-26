#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10788);
 script_cve_id("CVE-2001-1503");
 script_bugtraq_id(3457);
 script_version ("$Revision: 1.11 $");
 name["english"] = "Solaris finger disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a bug in the remote finger service which, when triggered, allows
a user to force the remote finger daemon to  display the list of the accounts 
that have never been used, by issuing the request :

		finger 'a b c d e f g h'@target
		
This list will help an attacker to guess the operating system type. It will 
also tell him which accounts have never been used, which will often make him 
focus his attacks on these accounts.

Solution : disable the finger service in /etc/inetd.conf and restart the inetd
process, or apply the relevant patches from Sun Microsystems.

Risk factor : Medium"; 

 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates users with finger";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Finger abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("a b c d e f g h\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);
  if(("daemon" >< data) && ("root" >< data) && ("nobody" >< data))
	{
  report = "
There is a bug in the remote finger service which, when triggered, allows
a user to force the remote finger daemon to  display the list of the accounts 
that have never been used, by issuing the request :

		finger 'a b c d e f g h'@target
		
This list will help an attacker to guess the operating system type. It will 
also tell him which accounts have never been used, which will often make him 
focus his attacks on these accounts.

Here is the data that could be gathered with the request above :

" + data + "

Solution : disable the finger service in /etc/inetd.conf and restart the inetd
process, or apply the relevant patches from Sun Microsystems.

Risk factor : Medium"; 
		security_warning(port:port, data:report);
	}
 }
}
