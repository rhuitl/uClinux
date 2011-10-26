#
# (C) Tenable Network Security
#


if (description) {
  script_id(17247);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0632");
  script_bugtraq_id(12696);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"14313");

  script_name(english:"PHPNews auth.php Remote File Include Vulnerability");

  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that suffers from a remote
file include vulnerability. 

Description :

The remote host is running PHPNews, an open-source news application
written in PHP. 

The installed version of PHPNews has a remote file include
vulnerability in the script 'auth.php'.  By leveraging this flaw, a
attacker can cause arbitrary PHP code to be executed on the remote
host using the permissions of the web server user. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-03/0026.html
http://newsphp.sourceforge.net/changelog/changelog_1.25.txt

Solution : 

Upgrade to PHPNews 1.2.5 or greater or make sure PHP's
'register_globals' and 'allow_url_fopen' settings are disabled.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects remote file include vulnerability in auth.php in PHPNews";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security.");

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
if (thorough_tests) dirs = make_list("/phpnews", "/news", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If the main page is from PHPNews...
  if ('<link href="phpnews_package.css"' >< res) {
    # Try the exploit by grabbing the site's PHPNews phpnews_package.css.
    exploit = string("/auth.php?path=http://", get_host_name(), dir, "/phpnews_package.css%00");
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If it looks like we got a stylesheet, there's a problem.
    if ("a:link {" >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
