#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Cedric Cochin
#
#  This script is released under the GNU GPL v2

if(description)
{
 script_id(15770);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2004-1055");
 script_bugtraq_id(11707); 
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"11930");
   script_xref(name:"OSVDB", value:"11931");
   script_xref(name:"OSVDB", value:"11932");
 }

 name["english"] = "phpMyAdmin XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is susceptible to
cross-site scripting attacks. 

Description :

The version of phpMyAdmin installed on the remote host is vulnerable
to cross-site scripting attacks through various parameters and
scripts.  With a specially crafted URL, an attacker can cause
arbitrary code execution resulting in a loss of integrity. 

See also :

http://www.netvigilance.com/html/advisory0005.htm

http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-3

Solution : 

Upgrade to phpMyAdmin version 2.6.0-pl3 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port) ) exit(0);


# Check an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if ( ereg(pattern:"^(2\.[0-5]\..*|2\.6\.0|2\.6\.0-pl[12]([^0-9]|$))", string:ver))
    security_note(port);
}
