#
# (C) Tenable Network Security
#


if (description) {
  script_id(17609);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0886");
  script_bugtraq_id(12888);

  script_name(english:"Invision Power Board IFRAME HTML Injection Vulnerability");

  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is vulnerable to a
cross-site scripting attack. 

Description :

The version of Invision Power Board installed on the remote host does
not properly sanitize HTML tags, which enables a remote attacker to
inject a malicious IFRAME when posting a message to one of the hosted
forums.  This could cause arbitrary HTML and script code to be
executed in the context of users browsing the forum, which may enable
an attacker to steal cookies or misrepresent site content. 

Solution : 

Upgrade to Invision Power Board 2.0.3 or later.

Risk factor : 

Low / CVSS Base Score : 1
(AV:R/AC:H/Au:R/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for IFRAME HTML Injection Vulnerability in Invision Power Board";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(1\.|2\.0\.[0-2][^0-9]*)") security_note(port);
}
