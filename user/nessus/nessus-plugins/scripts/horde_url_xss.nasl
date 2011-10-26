#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22004);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3548", "CVE-2006-3549");
  script_bugtraq_id(18845);

  script_name(english:"Horde url Parameter Cross-Site Scripting Vulnerabilities");
  script_summary(english:"Tries to exploit an XSS flaw in Horde's services/go.php");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by
multiple cross-site scripting vulnerabilities. 

Description :

The version of Horde installed on the remote host fails to validate
input to the 'url' parameter of the 'services/go.php' script before
using it in dynamically generated content.  An unauthenticated
attacker may be able to leverage this issue to inject arbitrary HTML
and script code into a user's browser. 

In addition, similar cross-site scripting issues reportedly exist with
the 'module' parameter of the 'services/help/index.php' script and the
'name' parameter of the 'services/problem.php' script. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-July/047687.html
http://lists.horde.org/archives/announce/2006/000287.html
http://lists.horde.org/archives/announce/2006/000288.html

Solution :

Upgrade to Horde 3.0.11 / 3.1.2 or later.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("horde_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple (and invalid) alert.
xss = string("javascript:alert(", SCRIPT_NAME, ")");


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to read a file.
  #
  # nb: Horde 3.x uses "/services"; Horde 2.x, "/util".
  foreach subdir (make_list("/services", "/util"))
  {
    req = http_get(
      item:string(
        dir, subdir, "/go.php?",
        "url=", urlencode(str:string("http://www.example.com/;url=", xss))
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if our XSS appears in the redirect.
    if (string("Refresh: 0; URL=http://www.example.com/;url=", xss) >< res)
    {
      security_note(port);
      exit(0);
    }
  }
}
