#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: Secure Reality Pty Ltd. Security Advisory #6 on December 6, 2000.
#
# This script is released under the GNU GPLv2
#


if(description)
{
 script_id(15711);
 script_bugtraq_id(2069);
 script_cve_id("CVE-2001-0043");
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"1682");
	
 script_version ("$Revision: 1.4 $");
 name["english"] = "PhpGroupWare arbitrary command execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running PhpGroupWare, is a multi-user groupware 
suite written in PHP.

This version is prone to a vulnerability that may permit remote attackers
to execute arbitrary commands by triggering phpgw_info parameter of the 
phpgw.inc.php script, resulting in a loss of integrity.

Solution : Update to version 0.9.7 of this software or newer
See also: http://www.phpgroupware.org/
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PhpGroupWare version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
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

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

if ( ereg(pattern:"^0\.([0-8]\.|9\.[0-6][^0-9])", string:matches[1]) ) 
	security_warning(port);
