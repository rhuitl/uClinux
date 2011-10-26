#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22300);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-4542");
  script_bugtraq_id(19820);
  script_xref(name:"OSVDB", value:"28337");
  script_xref(name:"OSVDB", value:"28338");

  script_name(english:"Webmin / Usermin Null Filtering Vulnerabilities");
  script_summary(english:"Checks if nulls in a URL are filtered by miniserv.pl");

  desc = "
Synopsis :

The remote web server is affected by multiple issues.

Description :

The remote host is running Webmin or Usermin, web-based interfaces for
Unix / Linux system administrators and end-users. 

Webmin and Usermin both come with the Perl script 'miniserv.pl' to
provide basic web services, and the version of 'miniserv.pl' installed
on the remote host fails to properly filter null characters from URLs. 
An attacker may be able to exploit this to reveal the source code of CGI
scripts, obtain directory listings, or launch cross-site scripting
attacks against the affected application. 

See also :

http://www.lac.co.jp/business/sns/intelligence/SNSadvisory_e/89_e.html
http://www.webmin.com/security.html

Solution :

Upgrade to Webmin version 1.296 / Usermin 1.226 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("webmin.nasl");
  script_require_ports("Services/www", 10000);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:10000);
if (!get_port_state(port)) exit(0);
if (!get_kb_item("www/" + port + "/webmin"));


# Some files don't require authentication; eg, those matching the
# pattern '^[A-Za-z0-9\\-/]+\\.gif'. So request a bogus gif file; if
# nulls are filtered, we'll get an error saying "Error - File not 
# found"; otherwise, we'll get a login form because the null will 
# cause the regex to fail.
req = http_get(item:string("/nessus%00.gif"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see a login form.
if ("<form action=/session_login.cgi " >< res) security_warning(port);
