#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10418);
 script_bugtraq_id(1080);
 script_cve_id("CVE-2000-0109");
 script_version ("$Revision: 1.11 $");

 name["english"] = "Standard & Poors detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be a Standard & Poor's MultiCSP system.

These systems are known to be very insecure, and an intruder may
easily break into it to use it as a launch pad for other attacks.


Solution : protect this host by a firewall
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect if the remote host is a Standard & Poors' MultiCSP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/telnet", 23);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#
include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (get_port_state(port))
{
 banner = get_telnet_banner(port: port);
 if(banner)
   {
   if("MCSP - Standard & Poor's ComStock" >< banner)
      security_hole(port:port, data:banner);
   }
}
