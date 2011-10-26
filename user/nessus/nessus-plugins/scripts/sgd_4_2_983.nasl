#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22495);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4958", "CVE-2006-4959");
  script_bugtraq_id(20135, 20276);

  script_name(english:"Sun Secure Global Desktop / Tarantella < 4.20.983 Cross-Site Scripting Vulnerabilities");
  script_summary(english:"Checks version of Sun Secure Global Desktop / Tarantella");

  desc = "
Synopsis :

The remote web server contains CGI scripts that are vulnerable to
cross-site scripting attacks. 

Description :

Sun Secure Global Desktop or Tarantella, a Java-based program for
web-enabling applications running on a variety of platforms, is
installed on the remote web server. 

According to the version reported in one of its scripts, the
installation of the software on the remote host fails to sanitize
user-supplied input to several unspecified parameters before using it
to generate dynamic web content.  An unauthenticated remote attacker
may be able to leverage these issues to inject arbitrary HTML and
script code into a user's browser to be evaluated within the security
context of the affected web site. 

See also :

http://www.securityfocus.com/archive/1/446566/30/0/threaded
http://sunsolve.sun.com/search/document.do?assetkey=1-26-102650-1

Solution :

Upgrade to Sun Secure Global Desktop version 4.20.983 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);



# Do a banner check.
req = http_get(
  item:"/tarantella/cgi-bin/secure/ttawlogin.cgi/?action=bootstrap", 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If there's a version...
if ('<PARAM NAME="TTAVersion"' >< res)
{
  # Extract it.
  pat = '^ *<PARAM NAME="TTAVersion" VALUE="([^"]+)">.*';
  line = egrep(pattern:pat, string:res);
  if (line)
  {
    ver = ereg_replace(pattern:pat, string:line, replace:"\1");
    if (ver)
    {
      # There's a problem if it's a version before 4.20.983.
      ver = split(ver, sep:'.', keep:FALSE);
      if (
        int(ver[0]) < 4 ||
        (
          int(ver[0]) == 4 &&
          (
            int(ver[1]) < 20 ||
            (int(ver[1]) == 20 && int(ver[2]) < 983)
          )
        )
      ) security_warning(port);
    }
  }
}

