#
# (C) Tenable Network Security
#


if (description)
{
 script_id(16071);
 script_version ("$Revision: 1.7 $");

 script_cve_id("CVE-2004-1423");
 script_bugtraq_id(12127);

 script_name(english:"PHP-Calendar Remote File Include Vulnerability");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include vulnerability. 

Description :

The remote web server is running PHP-Calendar, a web-based calendar
written in PHP. 

The remote version of this software is vulnerable to a file inclusion
flaw which may allow an attacker to execute arbitrary PHP commands on
the remote host. 

See also :

http://www.gulftech.org/?node=research&article_id=00060-12292004
http://archives.neohapsis.com/archives/bugtraq/2004-12/0441.html
http://sourceforge.net/project/shownotes.php?release_id=296020&group_id=46800

Solution : 

Upgrade to PHP-Calendar version 0.10.1 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if PHP-Calendar can include third-party files");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");

 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/includes/calendar.php?phpc_root_path=http://xxxx./");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL ) exit(0);
 if ( "http://xxxx./includes/html.php" >< buf )
 {
  security_hole(port);
  exit(0);
 }
}
