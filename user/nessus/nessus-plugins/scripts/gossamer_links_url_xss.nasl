#
# (C) Tenable Network Security
#


if (description) {
  script_id(19234);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1492");
  script_bugtraq_id(13484);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"16189");

  name["english"] = "Gossamer Links url Parameter Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is susceptible to a
cross-site scripting attack. 

Description :

The remote host is running Gossamer Links, a web links management tool
from Gossamer Threads and written in Perl. 

The installed version of Gossamer Links fails to properly sanitize
user-supplied input to the 'url' parameter of the 'user.cgi' script. 
By leveraging this flaw, an attacker may be able to cause arbitrary
HTML and script code to be executed by a user's browser within the
context of the affected application, leading to cookie theft and
similar attacks. 

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=111531023916998&w=2
http://www.nessus.org/u?a19428ee

Solution : 

Upgrade to Gossamer Links 3.0.1 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for url parameter cross-site scripting vulnerability in Gossamer Links";
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';
# nb: the url-encoded version is what we need to pass in.
exss = '%3Cscript%3Ealert("' + SCRIPT_NAME + '")%3B%3C%2Fscript%3E';


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/user.cgi?",
      'url=">', exss, "&",
      "from=add"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if ...
  if (
    # it looks like Gossamer Links and...
    '<input type="hidden" name="url" value="">' >< res &&
    # we see our XSS.
    xss >< res
  ) {
    security_note(port);
    exit(0);
  }
}
