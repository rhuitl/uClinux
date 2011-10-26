#
# This script is (C) Tenable Network Security
#


if(description)
{
 script_id(15543);
 script_version ("$Revision: 1.5 $");

 script_cve_id("CVE-2004-1620");
 script_bugtraq_id(11497);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"11013");
  script_xref(name:"OSVDB", value:"11038");
  script_xref(name:"OSVDB", value:"11039");
 }

 name["english"] = "Serendipity HTTP Response Splitting Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by a
cross-site scripting flaw. 

Description :

The remote version of Serendipity is vulnerable to an HTTP response-
splitting vulnerability that may allow an attacker to perform a cross-
site scripting attack against the remote host. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2004-10/0219.html
http://www.s9y.org/5.html

Solution : 

Upgrade to Serendipity 0.7rc1 or newer.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Serendipity";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencies("serendipity_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "0\.([0-6][^0-9]|7-b)") security_note(port);
}
