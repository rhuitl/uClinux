#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(16070);
 script_cve_id("CVE-2004-1420", "CVE-2004-1421", "CVE-2004-1422");
 script_bugtraq_id(12119);
 script_version ("$Revision: 1.5 $");

 script_name(english:"WHM AutoPilot Multiple Vulnerabilities");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from
several vulnerabilities. 

Description :

The remote web server is running WHM AutoPilot, a script designed to
administer a web-hosting environment. 

The remote version of this software is vulnerable to various flaws
that may allow an attacker to execute arbitrary commands on the remote
host, obtain information about the remote host's PHP installation, and
launch cross-site scripting attacks. 

See also :

http://www.gulftech.org/?node=research&article_id=00059-12272004

Solution : 

Upgrade to WHM AutoPilot version 2.5.20 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if WHM AutoPilot can include third-party files");
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
 url = string(d, "/inc/header.php/step_one.php?server_inc=http://xxxx./");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if ( "http://xxxx./step_one_tables.php" >< buf )
 {
  security_hole(port);
  exit(0);
 }
}
