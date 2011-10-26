#
# (C) Tenable Network Security
#


if (description) {
  script_id(20215);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2003-0536", "CVE-2005-0870", "CVE-2005-3347", "CVE-2005-3348");
  script_bugtraq_id(7286, 15396, 15414);

  script_name(english:"phpSysInfo < 2.4.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpSysInfo < 2.4.1");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running phpSysInfo, a PHP application that parses
the /proc entries on Linux/Unix systems and displays them in HTML. 

The installed version of phpSysInfo on the remote host has a design
flaw in its globalization layer such that the script's variables can
be overwritten independent of PHP's 'register_globals' setting.  By
exploiting this issue, an attacker may be able to read arbitrary files
on the remote host (if PHP's 'magic_quotes_gpc' setting is off) and
even execute arbitrary PHP code, both subject to the privileges of the
web server user id. 

In addition, the application fails to sanitize user-supplied input
before using it in dynamically-generated pages, which can be used to
conduct cross-site scripting and HTTP response splitting attacks. 

See also :

http://www.hardened-php.net/advisory_222005.81.html

Solution :

Upgrade to phpSysInfo 2.4.1 or later.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);
 
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/phpsysinfo", "/phpSysInfo", "/sysinfo", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit some of the flaws.
  req = http_get(
    item:string(
      dir, "/index.php?",
      # if successful, output will have the footer repeated.
      "lng=../system_footer&",
      # if successful, output will complain about an invalid sensor program.
      "sensor_program=", SCRIPT_NAME
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we overwrote $sensor_program.
  if (string("<b>Error: ", SCRIPT_NAME, " is not currently supported") >< res) {
    security_note(port);
    exit(0);
  }

  # Alternatively, there's a problem if there are two footers.
  footer = "</html>";
  post_footer = strstr(res, footer);
  if (post_footer) {
    post_footer = post_footer - footer;
    if (strstr(post_footer, footer)) {
      security_note(port);
      exit(0);
    }
  }
}
