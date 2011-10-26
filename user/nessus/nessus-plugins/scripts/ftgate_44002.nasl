#
# (C) Tenable Network Security
#


if (description) {
  script_id(20337);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4567", "CVE-2005-4568", "CVE-2005-4569");
  script_bugtraq_id(15972);
  script_xref(name:"OSVDB", value:"22104");
  script_xref(name:"OSVDB", value:"22105");
  script_xref(name:"OSVDB", value:"22106");
  script_xref(name:"OSVDB", value:"22107");

  script_name(english:"FTGate <= 4.4.002 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in FTGate <= 4.4.002");

  desc = "
Synopsis :

The remote mail server is affected by multiple flaws. 

Description :

The remote host appears to be running a version of FTGate, a
commercial groupware mail server for Windows from FTGate Technology
Ltd. 

The web server used to administer FTGate on the remote host fails to
sanitize input to the 'href' parameter of the 'index.fts' script
before using it to generate dynamic content.  An unauthenticated
attacker can leverage this flaw to inject arbitrary HTML and script
code into a user's browser, to be evaluated within the security
context of the affected application. 

In addition, there reportedly is a buffer overflow vulnerability in
the web server as well as several format string vulnerabilities in the
accompanying IMAP and POP3 services.  An unauthenticated attacker may
be able to exploit these issues to execute code on the affected host. 

See also : 

http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040390.html
http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040391.html
http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040392.html
http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040393.html

Solution : 

Upgrade to FTGate version 4.4.004 or later as it reportedly fixes
these issues. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8089);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:8089);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# nb: the web server doesn't have a banner.


# Try to exploit the XSS flaw.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>;';
req = http_get(
  item:string(
    "/index.fts?",
    # nb: FTGate apparently filters url-encode characters 
    #     unless they're upper-case.
    "href=", urlencode(str:string('">', xss), case:HEX_UPPERCASE)
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see our XSS.
if (
  "TITLE>FTGate Web Admin" >< res &&
  string('NAME="href" VALUE="">', xss) >< res
) {
  security_warning(port);
  exit(0);
}
