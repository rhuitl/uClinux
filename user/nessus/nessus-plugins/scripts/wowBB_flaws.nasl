#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Positive Technologies - www.maxpatrol.com
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15557);
  script_cve_id("CVE-2004-2180", "CVE-2004-2181");
  script_bugtraq_id(11429);
  script_version("$Revision: 1.7 $");
  script_name(english:"WowBB <= 1.61 multiple flaws");
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
multiple flaws. 

Description :

The remote host is running WowBB, a web-based forum written in PHP. 

According to its version, the remote installation of WowBB is 1.61 or
older.  Such versions are vulnerable to cross-site scripting and SQL
injection attacks.  A malicious user can steal users' cookies,
including authentication cookies, and manipulate SQL queries. 

See also : 

http://www.maxpatrol.com/advdetails.asp?id=7

Solution: 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

  script_description(english:desc["english"]);

  script_summary(english:"Checks WowBB version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
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
  r = http_get_cache(item:string(req, "/index.php"), port:port);
  if( r == NULL )exit(0);
  if(egrep(pattern:"WowBB Forums</TITLE>.*TITLE=.WowBB Forum Software.*>WowBB (0\..*|1\.([0-5][0-9]|60|61))</A>", string:r))
  {
 	security_note(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port))exit(0);

if (thorough_tests) dirs = make_list("/forum", "/forums", "/board", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) check(req:dir);
