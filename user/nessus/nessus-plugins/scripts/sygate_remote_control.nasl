#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10274);
 script_bugtraq_id(952);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0113");
 
 name["english"] = "SyGate Backdoor";
 script_name(english:name["english"]);
 
 desc["english"] = "
SyGate engine remote controller seems to be running on this port. 
It may be used by malicious users which are on the same subnet as this host
to reconfigure the remote SyGate engine.

Solution : Filter incoming traffic to this port
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects whether SyGate remote controller is running";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_require_ports(7323);
 exit(0);
}

#
# The script code starts here
#

include('telnet_func.inc');
port = 7323;
if (get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if("yGate" >< banner)security_hole(port);
}
