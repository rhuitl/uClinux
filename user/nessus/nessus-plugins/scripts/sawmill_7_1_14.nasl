#
# (C) Tenable Network Security
#


if (description) {
  script_id(19681);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2950");
  script_bugtraq_id(14789);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"19254");

  name["english"] = "Sawmill < 7.1.14 Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server suffers from a cross-site scripting
vulnerability. 

Description :

The remote host is running Sawmill, a weblog analysis package. 

The version of Sawmill installed on the remote host suffers from a
cross-site scripting flaw because its standalone web server treats an
arbitrary query string appended to a GET request as a configuration
command and fails to sanitize it before using it in an error page.  An
unauthenticated attacker may be able to exploit this issue to steal
authentication information of users of the affected application. 

See also : 

http://www.nta-monitor.com/news/xss/sawmill/index.htm
http://archives.neohapsis.com/archives/bugtraq/2005-09/0114.html

Solution : 

Upgrade to Sawmill 7.1.14 or later or use Sawmill in CGI mode.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cross-site scripting vulnerability in Sawmill < 7.1.14";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8987);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:8987);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# The flaw only affects Sawmill's built-in web server.
banner = get_http_banner(port:port);
if (banner && "Server: Sawmill/" >< banner) {
  req = http_get(
    item:string("/?", rand_str(), "=", exss),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (xss >< res) security_note(port);
}
