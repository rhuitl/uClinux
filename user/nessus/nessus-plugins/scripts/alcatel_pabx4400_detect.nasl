#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
   script_id(11019);
   script_version ("$Revision: 1.3 $");
   name["english"] = "Alcatel PABX 4400 detection";
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote host is an Alcatel PABX 4400.

This device can be configured thru the serial
port or using this port. 

Outsiders should not be able to connect to this device

Solution : filter incoming traffic to this host
Risk factor : Low";


   script_description(english:desc["english"]);
 
   summary["english"] = "Detects if the remote host is an Alcatel 4400";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
   
   script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
   script_family(english:"Service detection");
   script_require_ports(2533);
 
   exit(0);
}


#
# The code starts here
# 

port = 2533;
req = raw_string(0x00, 0x01, 0x43);
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:2);
 close(soc);
 if ( strlen(r) < 2 ) exit(0);
 r_lo = ord(r[0]);
 r_hi = ord(r[1]);
 if((r_lo == 0) && (r_hi == 1))security_note(port);
}
