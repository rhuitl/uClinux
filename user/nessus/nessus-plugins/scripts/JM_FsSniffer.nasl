#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
# 
# 

if(description)
{

script_id(11854);
script_version ("$Revision: 1.2 $");
name["english"] = "FsSniffer Detection";
script_name(english:name["english"]);

desc["english"] = "
This host appears to be running FsSniffer on this port.

FsSniffer is backdoor which allows an intruder to steal
PoP3/FTP and other passwords you use on your system.

An attacker may use it to steal your passwords.

Solution : see www.rapter.net/jm1.htm for details on removal
Risk factor : High";

script_description(english:desc["english"]);

summary["english"] = "Determines the presence of FsSniffer";

script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);


script_copyright(english:"This script is Copyright (C) 2003 J.Mlodzianowski");
family["english"] = "Backdoors";
script_family(english:family["english"]);
script_dependencie("find_service2.nasl");
exit(0);
}


#
# The code starts here
#

port =  get_kb_item("Services/RemoteNC");
if(port)security_hole(port);
