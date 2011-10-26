#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#

if(description)
{
script_id(20252);

script_cve_id("CVE-2005-3980");
script_bugtraq_id(15676);
script_xref(name:"OSVDB", value:"21386");

script_version("$Revision: 1.4 $");
script_name(english:"Edgewall Software Trac SQL injection flaw");


desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is affected by a SQL
injection flaw. 

Description:

The remote host is running Trac, an enhanced wiki and issue tracking
system for software development projects written in python. 

The remote version of this software is prone to a SQL injection flaw
through the ticket query module due to 'group' parameter is not
properly sanitized. 

See also: 

http://www.securityfocus.com/archive/1/418294/30/0/threaded
http://projects.edgewall.com/trac/wiki/ChangeLog

Solution: 

Upgrade to Trac version 0.9.1 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

script_description(english:desc["english"]);

script_summary(english:"Checks for SQL injection flaw in Trac");
script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
script_family(english:"CGI abuses");
script_exclude_keys("Settings/disable_cgi_scanning");
script_require_ports("Services/www");
exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port))exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/trac", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
	buf = http_get(item:string(dir,"/query?group=/*"), port:port);
	r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
	if( r == NULL )exit(0);
	if("Trac detected an internal error" >< r && egrep(pattern:"<title>Oops - .* - Trac<", string:r))
	{
		security_warning(port);
		exit(0);
	}
}
