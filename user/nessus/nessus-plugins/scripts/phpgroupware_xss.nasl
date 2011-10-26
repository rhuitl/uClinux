#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14708);
 script_bugtraq_id(11130);
 script_cve_id("CVE-2004-0875");
 script_version ("$Revision: 1.7 $");
 name["english"] = "PhpGroupWare XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running PhpGroupWare, is a multi-user groupware 
suite written in PHP.

This issue exists due to a lack of sanitization of user-supplied data.
A malicious attacker can exploited a flaw to conduct cross-site scripting 
attacks.

Solution : Update to version 0.9.16.003 or newer
See also : http://www.phpgroupware.org/
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PhpGroupWare version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:matches[0]);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.|16\.0*[0-2]([^0-9]|$)))", string:matches[1]))
	security_warning(port);
