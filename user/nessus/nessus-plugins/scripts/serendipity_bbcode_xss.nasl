#
# (C) Tenable Network Security
#


if (description) {
  script_id(18155);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1448");
  script_bugtraq_id(13411);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15876");

  name["english"] = "Serendipity BBCode Plugin Cross-Site Scripting Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
cross-site scripting attacks. 

Description :

According to its banner, the version of Serendipity installed on the
remote host does not properly filter user-supplied input for selected
fields if the BBCode plugin is enabled - it is not by default.  By
exploiting this flaw, an attacker can cause arbitrary HTML and script
code to be executed by a user's browser in the context of the affected
web site whenever users view malicious entries or comments that the
attacker creates. 

See also :

http://www.s9y.org/63.html#A9

Solution : 

Disable the BBCode plugin or upgrade to Serendipity 0.8 or later. 

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cross-site scripting vulnerabilities in Serendipity BBCode plugin";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("serendipity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: version 0.8 fixes the flaw.
  if (ver =~ "0\.([0-7]|8-beta)") security_note(port);
}
