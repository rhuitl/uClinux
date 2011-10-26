#
# (C) Tenable Network Security
#


if (description) {
  script_id(19515);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2736", "CVE-2005-4799", "CVE-2006-4421");
  script_bugtraq_id(14670, 15092, 15095, 19709);
  if (defined_func("script_xref"))
  {
    script_xref(name:"OSVDB", value:"19958");
    script_xref(name:"OSVDB", value:"19959");
  }

  name["english"] = "YaPiG <= 0.9.5b Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
code injection and cross-site scripting attacks.

Description :

The remote host is running YaPiG, a web-based image gallery written in
PHP. 

According to its banner, the version of YaPiG installed on the remote
host is prone to arbitrary PHP code injection and cross-site scripting
attacks. 

See also :

http://cedri.cc/advisories/EXIF_XSS.txt
http://www.seclab.tuwien.ac.at/advisories/TUVSA-0510-001.txt
http://archives.neohapsis.com/archives/bugtraq/2006-08/0483.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in YaPiG <= 0.9.5b";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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


if (thorough_tests) dirs = make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Pull up the main page.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  # Check the version number of YaPiG.
  if (
    egrep(
      string:res, 
      pattern:"Powered by <a href=.+>YaPiG.* V0\.([0-8][0-9]($|[^0-9])|9([0-4]|5[.ab]))"
    )
  ) {
    security_warning(port);
    exit(0);
  }
}
