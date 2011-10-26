#
# (C) Tenable Network Security
#


if (description) {
  script_id(18540);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2021");
  script_bugtraq_id(13996);

  name["english"] = "cPanel user Parameter Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a script that is prone to a cross-site
scripting attack. 

Description :

The remote host is running cPanel.

The version of cPanel on the remote host suffers from a cross-site
scripting vulnerability due to its failure to sanitize user-supplied
input to the 'user' parameter of the 'login' page.  An attacker may be
able to exploit this flaw to inject arbitrary HTML and script code
into a user's browser. 

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for user parameter cross-site scripting vulnerability in cPanel";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 2086);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:2086);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


xss = "regex m/^** << HERE <script>JavaScript:alert('" + SCRIPT_NAME + "');</script>";
exss = "%3Cscript%3EJavaScript:alert('" + SCRIPT_NAME + "')%3B%3C%2Fscript%3E";

req = http_get(item:string("/login?user=**", exss), port:port);
# bodyonly set to FALSE as cPanel does not return a proper HTTP header on errors
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);

if (xss >< res) security_note(port);
