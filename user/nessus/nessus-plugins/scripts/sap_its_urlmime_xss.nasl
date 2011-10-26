#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22465);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-5114");
  script_bugtraq_id(20244);

  script_name(english:"SAP Internet Transaction Server urlmime Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks for an XSS flaw in SAP Internet Transaction Server");

  desc = "
Synopsis :

The remote web server contains a CGI script that is vulnerable to a
cross-site scripting attack. 

Description :

The remote web server fails to sanitize the contents of the 'urlmime'
parameter to the '/scripts/wgate' script before using it to generate
dynamic web content.  An unauthenticated remote attacker may be able
to leverage this issue to inject arbitrary HTML and script code into a
user's browser to be evaluated within the security context of the
affected web site. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2006-09/0467.html

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);



# Generate a request to exploit the flaw.
xss = string('"><script>alert("', SCRIPT_NAME, '")</script><img src="');
req = http_get(
  item:string("/scripts/wgate/!?~urlmime=", urlencode(str:xss)), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if...
if (
  # it's SAP ITS and...
  "SAP Internet Transaction Server" >< res &&
  # we see our exploit
  (
    string('<td background="', xss) >< res ||
    string('><img src="', xss) >< res ||
    # nb: this vector requires a minor tweak in the published exploit
    #     to actually pop up an alert.
    string('language="JavaScript1.2" src=', "'", xss) >< res
  )
) security_warning(port);
