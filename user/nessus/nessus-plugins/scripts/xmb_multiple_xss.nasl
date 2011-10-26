#
# (C) Tenable Network Security
#


if (description) {
  script_id(17608);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0885", "CVE-2005-2574", "CVE-2005-2575");
  script_bugtraq_id(12886, 14523);

  script_name(english:"XMB Forum < 1.9.2 Multiple Vulnerabilities");
  desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone
to multiple issues.

Description :

The remote host is running XMB Forum, a web forum written in PHP.

According to its banner, the version of XMB installed on the remote host
suffers from cross-site scripting, SQL injection, and input validation
vulnerabilities. 

See also : 

http://forums.xmbforum.com/viewthread.php?tid=754523
http://marc.theaimsgroup.com/?l=bugtraq&m=112361545228809&w=2

Solution : 

Upgrade to XMB 1.9.2 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for multiple vulnerabilities in XMB Forum < 1.9.2");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Check various directories for XMB.
if (thorough_tests) dirs = make_list("/xmb", "/forum", "/forums", "/board", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Look for the version number in the login script.
  req = http_get(item:string(dir, "/misc.php?action=login"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # To actually exploit the vulnerabilities reliably, you need
  # to be logged in so the best we can do is a banner check.
  if (
    # Sample banners:
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.05</font><br />
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.5 RC4: Summer Forest<br />
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 Magic Lantern Final<br></b>
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 v2b Magic Lantern Final<br></b>
    #   Powered by XMB 1.8 Partagium SP1<br />
    #   Powered by XMB 1.9 Nexus (beta)<br />
    #   Powered by XMB 1.9.1 RC1 Nexus<br />
    #   Powered by XMB 1.9.2 Nexus (pre-Alpha)<br />
    egrep(string:res, pattern:"Powered by .*XMB(<[^>]+>)* v?(0\..*|1\.([0-8]+\..*|9(\.[01])?)) ")
  ) {
    security_warning(port);
    exit(0);
  }
}
