#
# (C) Tenable Network Security
#


if (description) {
  script_id(20969);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0800", "CVE-2006-0801", "CVE-2006-0802");
  script_bugtraq_id(16752);

  script_name(english:"PostNuke < 0.762 Multiple Vulnerabilities");
  script_summary(english:"Checks for admin access bypass issue in PostNuke");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that suffers from
multiple flaws. 

Description :

The installed version of PostNuke allows an unauthenticated attacker
to gain administrative access to select modules through a simple GET
request.  Additionally, it may be prone to various SQL injection
injection or cross-site scripting attacks as well as unspecified
attacks through the Languages module. 

See also :

http://securityreason.com/achievement_securityalert/33
http://lists.grok.org.uk/pipermail/full-disclosure/2006-February/042360.html
http://news.postnuke.com/index.php?name=News&file=article&sid=2754

Solution :

Upgrade to PostNuke 0.762 or later. 

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("postnuke_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the admin access bypass issue.
  req = http_get(item:string(dir, "/admin.php?module=Banners"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # There's a problem if we're granted access.
  if ('<a href="admin.php?module=Banners&amp;op=getConfig">Banners configuration' >< res) {
    security_warning(port);
  }
}
