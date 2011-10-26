#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22231);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-4267", "CVE-2006-4268");
  script_bugtraq_id(19563);
  script_xref(name:"OSVDB", value:"27984");
  script_xref(name:"OSVDB", value:"27985");
  script_xref(name:"OSVDB", value:"27986");
  script_xref(name:"OSVDB", value:"27987");

  script_name(english:"CubeCart < 3.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks for a XSS flaw in CubeCart");

  desc = "
Synopsis :

The remote web server contains a PHP application that suffers from
several flaws. 

Description :

The version of CubeCart installed on the remote host fails to properly
sanitize user-supplied input to several parameters and scripts before
using it in database queries and to generate dynamic web content.  An
unauthenticated attacker may be able to exploit these issues to
conduct SQL injection and cross-site scripting attacks against the
affected application. 

See also :

http://retrogod.altervista.org/cubecart_3011_adv.html
http://www.cubecart.com/site/forums/index.php?showtopic=21247

Solution :

Either apply the patches referenced in the vendor advisory above or
upgrade to CubeCart version 3.0.12 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("cubecart_detect.nasl", "cross_site_scripting.nasl");
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
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = string('<script>alert("', SCRIPT_NAME, '")</script>');


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit one of the XSS flaws as it works regardless of any PHP
  # settings and exists in several earlier versions.
  req = http_get(
    item:string(
      dir, "/admin/login.php?",
      "email=", urlencode(str:xss)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (string("password has been emailed to ", xss) >< res)
  {
    security_warning(port);
    exit(0);
  }
}
