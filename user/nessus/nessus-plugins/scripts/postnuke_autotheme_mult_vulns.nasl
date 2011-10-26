#
# (C) Tenable Network Security
#


if (description) {
  script_id(18300);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1608");
  script_bugtraq_id(13539);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"16346");

  name["english"] = "AutoTheme PostNuke Module Multiple Unspecified Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that suffers from multiple
issues. 

Description :

According to its banner, the version of AutoTheme for PostNuke on the
remote host suffers from multiple, unspecified vulnerabilities
affecting the 'Blocks' module.  Reportedly, some of these issues may
allow a remote attacker to gain unauthorized access to the remote
host. 

Note that the recommended security fix does not alter AutoTheme's
banner so if you know for certain that it's been applied, treat this
as a false positive. 

See also : 

http://community.postnuke.com/Article2687.htm

Solution : 

Apply the Blocks module Security Fix referenced in the URL or upgrade
to a newer version of the software when available. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple unspecified vulnerabilities in AutoTheme PostNuke module";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


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

  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # Check for AutoTheme's banner.
  pat = "^\*+ (AutoTheme|AT-Lite) ([^*]+) \*+$";
  matches = egrep(string:res, pattern:pat, icase:TRUE);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      banner = eregmatch(pattern:pat, string:match);
      # Extract the product and version number.
      if (!isnull(banner)) {
        prod = banner[1];
        ver = banner[2];

        # Check whether the software is vulnerable.
        if (
          (prod =~ "AutoTheme" && ver =~ "^(0\.|1\.([0-6][^0-9]|7\.0))") ||
          (prod =~ "AT-Lite" && ver =~ "^\.([0-7][^0-9]?|8$)")
        ) {
          security_warning(port);
          exit(0);
        }
      }
    }
  }
}
