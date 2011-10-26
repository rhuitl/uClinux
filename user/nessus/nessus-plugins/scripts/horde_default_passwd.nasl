#
# (C) Tenable Network Security
#


if (description) {
  script_id(20171);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3344");
  script_bugtraq_id(15337);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"24117");

  script_name(english:"Horde Default Admin Password Vulnerability");
  script_summary(english:"Checks for default admin password vulnerability in Horde");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that uses a default
administrative password. 

Description :

The remote installation of horde uses an administrative account with
no password.  An attacker can leverage this issue to gain full control
over the affected application and to run arbitrary shell, PHP, and SQL
commands using the supplied admin utilities. 

Note that while the advisory is from Debian, the flaw is not specific
to that distribution - any installation of Horde that has not been 
completely configured is vulnerable.

See also :

http://www.debian.org/security/2005/dsa-884
http://www.horde.org/horde/docs/?f=INSTALL.html#configuring-horde

Solution :

Either remove Horde or complete its configuration by configuring
an authentication backend.

Risk factor :

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("horde_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to access the login script.
  req = http_get(item:string(dir, "/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get in. [If it were configured, we'd
  # get redirected back to login.php.]
  if ('<frame name="horde_' >< res) security_hole(port);
}
