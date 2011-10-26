#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21220);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1627", "CVE-2006-1785", "CVE-2006-1786", "CVE-2006-1787", "CVE-2006-1788");
  script_bugtraq_id(17500);

  script_name(english:"Adobe Document Server for Reader Extensions < 6.1 Multiple Vulnerabilities");
  script_summary(english:"Tries to exploit an XSS flaw in Adobe Document Server for Reader Extensions");
 
  desc = "
Synopsis :

The remote web server is affected by multiple flaws. 

Description :

The remote host is running Adobe Document Server, a server that
dynamically creates and manipulates PDF documents as well as graphic
images. 

The version of Adobe Document Server installed on the remote host
includes the Adobe Document Server for Reader Extensions component,
which itself is affected by several issues :

  - Missing Access Controls
    An authenticated user can gain access to functionality to which 
    they should not have access by manipulating the 'actionID' and
    'pageID' parameters.

  - Cross-Site Scripting Flaws
    The application fails to sanitize input to several parameters
    before using it to generate dynamic web content.

  - Information Disclosure
    The application exposes a user's session id in the Referer
    header, which can lead to a loss of confidentiality. Also,
    the application returns different error messages during
    unsuccessful authentication attempts, which can be used to
    enumerate users.

See also :

http://secunia.com/secunia_research/2005-68/advisory/
http://www.adobe.com/support/techdocs/322699.html
http://www.adobe.com/support/techdocs/331915.html
http://www.adobe.com/support/techdocs/331917.html

Solution :

Upgrade to Adobe Document Server for Reader Extensions 6.1 / LiveCycle
Reader Extensions 7.0 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8019);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:8019);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';


# Try to exploit one of the XSS flaws.
req = http_get(
  item:string(
    "/altercast/AlterCast?", 
    "op=", urlencode(str:xss)
  ),
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see our XSS.
if ("/altercast/images/AdobeLogo.gif" >< res && string("<h2>", xss) >< res)
  security_warning(port);
