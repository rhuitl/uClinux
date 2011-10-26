#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Megasky <magasky@hotmail.com>
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(18221);
  script_cve_id("CVE-2005-1554");
  script_bugtraq_id(13569);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16543");
  }

  script_version("$Revision: 1.7 $");
  script_name(english:"WowBB view_user.php SQL Injection Flaw");
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by
a SQL injection flaw.

Description :

The remote host is running WowBB, a web-based forum written in PHP. 

The remote version of this software is vulnerable to SQL injection
attacks through the script 'view_user.php'.  A malicious user can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, attacks against the underlying
database, and the like. 

See also :

http://www.securityfocus.com/archive/1/399637

Solution: 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

  script_description(english:desc["english"]);

  script_summary(english:"Checks for SQL injection flaw in wowBB");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

function check(req)
{
  buf = http_get(item:string(req,"/view_user.php?list=1&letter=&sort_by='select"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if ("Invalid SQL query: SELECT" >< r && 'TITLE="WowBB Forum Software' >< r)
  {
 	security_warning(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port))exit(0);

if (thorough_tests) dirs = make_list("/forum", "/forums", "/board", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir ( dirs ) check(req:dir);
