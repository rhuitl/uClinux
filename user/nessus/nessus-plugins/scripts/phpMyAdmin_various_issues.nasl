#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15948);
 script_version("$Revision: 1.5 $");

 script_bugtraq_id(11886); 
 script_cve_id("CVE-2004-1147", "CVE-2004-1148");
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12330");
   script_xref(name:"OSVDB", value:"12331");
 }

 name["english"] = "phpMyAdmin Multiple Remote Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

According to its banner, the remote version of phpMyAdmin is
vulnerable to one (or both) of the following flaws :

- An attacker may be able to exploit this software to execute
arbitrary commands on the remote host on a server which does not run
PHP in safe mode. 

- An attacker may be able to read arbitrary files on the remote host
through the argument 'sql_localfile' of the file 'read_dump.php'. 

See also :

http://www.exaprobe.com/labs/advisories/esa-2004-1213.html
http://archives.neohapsis.com/archives/bugtraq/2004-12/0115.html
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-4

Solution : 

Upgrade to phpMyAdmin version 2.6.1-rc1 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/" + port + "/phpMyAdmin");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
# Only 2.4.0 to 2.6.0plX affected
if (matches[1] && ereg(pattern:"^(2\.[45]\..*|2\.6\.0|2\.6\.0-pl)", string:matches[1]))
	security_warning(port);
