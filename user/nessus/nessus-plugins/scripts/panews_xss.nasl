#
# (C) Tenable Network Security
#


if(description)
{
 script_id(16479);
 script_version("$Revision: 1.4 $");

 script_cve_id("CVE-2005-0485");
 script_bugtraq_id(12576);

 name["english"] = "paNews showpost Parameter Cross-Site Scripting Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by a
cross-site scripting issue. 

Description :

According to its banner, the remote host is running a version of
paNews that fails to sanitize input to the 'showpost' parameter of the
'comment.php' script before using it to generate dynamic web content. 
By coercing an unsuspecting user into visiting a malicious website, an
attacker may be able to possibly steal credentials or execute
browser-side code. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-02/0239.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks version of paNews";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 
 script_dependencies("panews_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/panews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver && ver =~  "^([0-1]\.|2\.0b[0-4])$") security_note(port);
}
