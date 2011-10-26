#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
# 

if(description)
{
 script_id(11369);
 script_bugtraq_id(1106, 4642);
 script_cve_id("CVE-2000-0283", "CVE-2000-1193");
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "irix performance copilot";

 script_name(english:name["english"]);
 
 desc["english"] = "
The service 'IRIX performance copilot' is running.

This service discloses sensitive informations about
the remote host, and may be used by an attacker to
perform a local denial of service.

*** This warning may be a false positive since the presence
*** of the bug was not verified locally.
    
Solution : Disable this service
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the presence of IRIX copilot";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc."; 

 script_family(english:family["english"]);
 script_require_ports(4321);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = 4321;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 r = recv(socket:soc, length:20);
 m = raw_string(0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00);
 if(m >< r) {
 	register_service(port:port, proto:"copilot");
 	security_hole(port);
	}
}
