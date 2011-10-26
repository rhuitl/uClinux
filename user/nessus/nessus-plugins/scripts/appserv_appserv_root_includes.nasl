#
# (C) Tenable Network Security
#


if (description) {
  script_id(20383);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0125");
  script_bugtraq_id(16166);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"22228");
  }

  script_name(english:"AppServ appserv_root Parameter Remote File Include Vulnerability");
  script_summary(english:"Checks for appserv_root parameter remote file include vulnerability in AppServ");
 
  desc = "
Synopsis :

The remote web server is prone to a remote file inclusion
vulnerability. 

Description :

The remote host appears to be running AppServ, a compilation of
Apache, PHP, MySQL, and phpMyAdmin for Windows and Linux. 

The version of AppServ installed on the remote host fails to sanitize
user-supplied input to the 'appserv_root' parameter of the
'appserv/main.php' script before using it in a PHP 'include' function. 
An unauthenticated attacker can exploit this flaw to run arbitrary
code, possibly taken from third-party hosts, subject to the privileges
of the web server user id.  Note that AppServ under Windows runs with
SYSTEM privileges, which means an attacker can gain complete control
of the affected host. 

Solution :

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Try to exploit the flaw.
#
# nb: AppServ is always installed under "/appserv".
req = http_get(
  item:string("/appserv/main.php?appserv_root=", SCRIPT_NAME), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# There's a problem if we get an error saying "failed to open stream".
if (egrep(pattern:string(SCRIPT_NAME, "/lang-.+\\.php\\): failed to open stream"), string:res)) {
  security_note(port);
  exit(0);
}
