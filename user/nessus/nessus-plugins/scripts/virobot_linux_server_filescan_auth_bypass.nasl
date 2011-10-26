#
# (C) Tenable Network Security
#


if (description) {
  script_id(20968);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0864");
  script_bugtraq_id(16768);

  script_name(english:"ViRobot Linux Server filescan Authentication Bypass Vulnerability");
  script_summary(english:"Checks for authentication bypass vulnerability in ViRobot Linux Server's filescan component");
 
  desc = "
Synopsis :

The remote web server is affected by an authentication bypass flaw. 

Description :

The remote host is running ViRobot Linux Server, a commercial
anti-virus application server. 

The installed version of ViRobot Linux Server has a flaw such that an
attacker can bypass authentication and gain access to its 'filescan'
component by supplying a special cookie.  An unauthenticated attacker
may be able to leverage this flaw to delete arbitrary files on the
remote host or disable access to the service by submitting scans of a
large number of large files on the remote host. 

See also :

http://www.securityfocus.com/archive/1/425788/30/0/threaded
http://www.hauri.net/download/download_linux_patch.php

Solution :

Apply the vendor patch referenced above.

Risk factor : 

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Try to exploit the flaw.
req = http_get(item:string("/cgi-bin/filescan"), port:port);
req = str_replace(
  string:req,
  find:"User-Agent:",
  replace:string(
    "Cookie: HTTP_COOKIE=test\r\n",
    "User-Agent:"
  )
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# There's a problem if we gained access.
if (
  "<title>ViRobot Linux Server" >< res &&
  "<form name=dir_form method=post" >< res
) {
  security_hole(port);
}
