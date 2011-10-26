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
 script_id(10502);
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "Axis Camera Default Password";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be an Axis Network Camera, using
the default login/password 'root/pass'.

An attacker may log into this host to change
its settings, such as its arp address, and create
some disorder on the network.

Solution : change its password
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects whether an Axis Network Camera has its default pass set";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(23);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('telnet_func.inc');
include('global_settings.inc');
if ( ! thorough_tests )exit(0);

port = 23;
if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
   banner = telnet_negotiate(socket:soc);
   req = string("root\r\n");
   send(socket:soc, data:req);
   recv(socket:soc, length:1000);
   req = string("pass\r\n");
   send(socket:soc, data:req);
   r = recv(socket:soc, length:1000);
   if("Root" >< r)security_warning(port);
   close(soc);
 }
}
