#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(19754);
 script_bugtraq_id(14724);
 script_version ("$Revision: 1.1 $");
 name["english"] = "PhpGroupWare Main Screen Message Script Injection Flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running PhpGroupWare, is a multi-user groupware 
suite written in PHP.

This version is vulnerable to script injection, a malicious admin can inject
script code into the main screen message.

Solution : Update to version 0.9.16.007 or newer.
See also : http://www.phpgroupware.org/
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PhpGroupWare version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses : XSS";
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

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.|16\.0[0-6]([^0-9]|$)))", string:matches[1]))
	security_warning(port);
