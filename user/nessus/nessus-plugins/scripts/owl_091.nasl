#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22232);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4211", "CVE-2006-4212");
  script_bugtraq_id(19552);

  script_name(english:"Owl Intranet Engine <= 0.91 Multiple Vulnerabilities");
  script_summary(english:"Checks for SQL injection flaw in Owl Intranet Engine");

  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
several issues. 

Description :

The remote host is running Owl Intranet Engine, a web-based document
management system written in PHP. 

The version of Owl Intranet Engine on the remote host fails to
sanitize input to the session id cookie before using it in a database
query.  Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated attacker may be able to exploit this issue to uncover
sensitive information such as password hashes, modify data, launch
attacks against the underlying database, etc. 

In addition, the application reportedly suffers from at least one
cross-site scripting issue. 

See also :

http://sourceforge.net/forum/forum.php?forum_id=601910

Solution :

Apply the patch referenced in the vendor advisory above. 

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
if (thorough_tests) dirs = make_list("/owl", "/intranet", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to generate a SQL syntax error.
  req = http_get(item:string(dir, "/index.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: owl_sessid='", SCRIPT_NAME, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see an error message with our script name.
  if (string("sessions where sessid = ''", SCRIPT_NAME) >< res)
  {
    security_warning(port);
    exit(0);
  }
}
