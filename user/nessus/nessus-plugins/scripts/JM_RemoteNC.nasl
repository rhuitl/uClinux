#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
#                            thanks to H.D.Moore
# 
#


if(description)
{

 script_id(11855);
 script_version ("$Revision: 1.3 $");
# script_cve_id("CVE-2003-00002");
 name["english"] = "RemoteNC detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This host appears to be running RemoteNC on this port

RemoteNC is a Backdoor which allows an intruder gain
remote control of your computer.

An attacker may use it to steal your passwords.

Solution : see www.rapter.net/jm2.htm for details on removal
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of RemoteNC";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 J.Mlodzianowski");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "JM_FsSniffer.nasl");
 exit(0);
}


#
# The code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/RemoteNC");
if (!port) exit(0);

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

r = recv(socket:soc, min:1, length:30);
if(!r) exit(0);

if("RemoteNC Control Password:" >< r)  security_hole(port);
