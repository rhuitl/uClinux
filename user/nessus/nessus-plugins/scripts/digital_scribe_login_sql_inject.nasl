#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: retrogod at aliceposta.it
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(19770);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2987");
  script_bugtraq_id(14843);
  script_xref(name:"OSVDB", value:"19460");

  script_name(english:"Digital Scribe login.php SQL Injection flaw");
 
 desc["english"] = "
Synopsis : 

The remote web server contains a PHP script which is vulnerable to a SQL
injection. 

Description : 

The remote web server hosts Digital Scribe, a student-teacher set of
scripts written in PHP.

The version of Digital Scribe installed on the remote host is prone to
SQL injection attacks through the 'login.php' script.  A malicious
user may be able to exploit this issue to manipulate database queries
to, say, bypass authentication. 

See also :

http://retrogod.altervista.org/dscribe14.html

Solution: 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";

  script_description(english:desc["english"]);

  script_summary(english:"Checks for SQL injection flaw in Digital Scribe");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

function check(req)
{
  buf = http_get(item:string(req,"/login.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if (("<TITLE>Login Page</TITLE>" >< r) && (egrep(pattern:"www\.digital-scribe\.org>Digital Scribe v\.1\.[0-4]$</A>", string:r)))
  {
 	security_note(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port))exit(0);

if (thorough_tests) dirs = make_list("/DigitalScribe", "/scribe", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  check(req:dir);
}
