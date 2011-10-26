#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11045);
 script_cve_id("CVE-2002-1974");
 script_bugtraq_id(5200);
 script_version ("$Revision: 1.7 $");

 script_name(english:"Passwordless Zaurus FTP server");
	     
 script_description(english:"
The remote Zaurus FTP server can be accessed as the user 'root' with no
password.

An attacker may use this flaw to steal the content of your PDA, 
including (but not limited to) your address book, personal files
and list of appointements. In addition to this, an attacker may
modify these files.

Solution: None at this time. Unplug your Zaurus from the network.
Risk factor : High");

 script_summary(english:"Logs into the remote Zaurus FTP server");

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 script_require_ports(4242);
 exit(0);
}

#
# The script code starts here : 
#

include('ftp_func.inc');
port = 4242;
if(!port)port = 21;

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 r = ftp_authenticate(socket:soc, user:"root", pass:"");
 if(r)
 {
  security_hole(port);
 }
 close(soc);
}
