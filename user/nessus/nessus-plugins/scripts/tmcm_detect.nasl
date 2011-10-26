#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#
if(description)
{
 script_id(18178);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Trend Micro TMCM console management detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to run Trend Micro Control Manager, connections 
are allowed to the web console management.

Letting attackers know that you are using this software will help them to 
focus their attack or will make them change their strategy.

Solution : Filter incoming traffic to this port
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Trend Micro TMCM console management";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("httpver.nasl");

 script_require_ports(80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port || port != 80 ) exit(0);

if(get_port_state(port))
{
 req = http_get(item:"/ControlManager/default.htm", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

#<title>
#Trend Micro Control Manager 3.0
#</title>

 if (egrep(pattern:"Trend Micro Control Manager.+</title>", string:rep, icase:1))
 {
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
	security_note(port);
 }
}
