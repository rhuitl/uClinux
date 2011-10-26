#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(16060);
 script_cve_id("CVE-2004-2602", "CVE-2004-2603");
 script_bugtraq_id(12105);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12597");
   script_xref(name:"OSVDB", value:"12598");
   script_xref(name:"OSVDB", value:"12631");
 }
 script_version ("$Revision: 1.3 $");

 script_name(english:"Help Center Live Multiple Vulnerabilities");
 desc["english"] = "
The remote web server is running Help Center Live, an help desk application
written in PHP.

The remote version of this software is vulnerable to various flaws which
may allow an attacker to execute arbitrary commands on the remote host.

Solution : Upgrade the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if Help Center Live can include third-party files");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/inc/pipe.php?HCL_path=http://xxxxxx./");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if ( "http://xxxxxx./inc/DecodeMessage.inc" >< buf )
 {
  security_hole(port);
  exit(0);
 }
}
