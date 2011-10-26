#
# (C) Tenable Network Security
#


if (description) {
  script_id(17350);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0783", "CVE-2005-0784");
  script_bugtraq_id(12800);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14660");
    script_xref(name:"OSVDB", value:"14823");
  }

  name["english"] = "Phorum Multiple Subject and Attachment Cross-Site Scripting and HTML Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that suffers from multiple
cross-site scripting flaws. 

Description :

The version of Phorum installed on the remote host is prone to
multiple cross-site scripting vulnerabilities due to its failure to
sanitize user input.  An attacker can exploit these flaws to
potentially cause arbitrary script and HTML code to be rendered by a
user's browser in the context of the vulnerable site. 

See also : 

http://www.securityfocus.com/archive/1/393192
http://www.phorum.org/story.php?48

Solution : 

Upgrade to Phorum 5.0.15 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple subject and attachment cross-site scripting and HTML injection vulnerabilities in Phorum";
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
#
# nb: actually testing for this is difficult because each forum can be
#     configured to allow anonymous users to create new threads, reply
#     to existing ones, and/or upload files and, by default in at
#     at least 5.0.15, these 3 settings are disabled.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: Bugtraq advisory says 5.0.14 and possibly earlier are affected.
  if (ver =~ "^([0-4].*|5\.0\.([0-9][^0-9]*|1[0-4][^0-9]*))$")
    security_note(port);
}
