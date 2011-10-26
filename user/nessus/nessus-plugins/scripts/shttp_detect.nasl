# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Refereces:
# RFC 2660 The Secure HyperText Transfer Protocol
#

if(description)
{
 script_id(11720);
#script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "S-HTTP detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This web server supports S-HTTP, a cryptographic layer 
that was defined in 1999 by RFC 2660. 
S-HTTP has never been widely implemented and you should 
use HTTPS instead.

As rare or obsolete code is often badly tested, it would be 
safer to use another server or disable this layer somehow.

Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if the web server accepts the Secure method";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "General";
 family["francais"] = "General";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

soc = http_open_socket(port);
if(!soc)exit(0);
req = string("Secure * Secure-HTTP/1.4\r\n",
		"Host: ", get_host_name(), ":", port, "\r\n",
		"Connection: close\r\n",
		"\r\n");
send(socket: soc, data: req);
r = recv_line(socket: soc, length: 256);
http_close_socket(soc);
if (ereg(pattern:"Secure-HTTP/[0-9]\.[0-9] 200 ", string:r)) security_warning(port);
