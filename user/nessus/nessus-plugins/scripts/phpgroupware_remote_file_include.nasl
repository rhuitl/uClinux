#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPLv2


if(description)
{
 script_id(14294);
 script_bugtraq_id(8265);
 script_version ("$Revision: 1.6 $");
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"2243");
 name["english"] = "PhpGroupWare unspecified remote file include vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running PhpGroupWare, is a multi-user groupware 
suite written in PHP.

This version is prone to a vulnerability that may permit remote attackers, 
without prior authentication, to include and execute malicious PHP scripts. 
Remote users may influence URI variables to include a malicious PHP script 
on a remote system, it is possible to cause arbitrary PHP code to be executed. 

Solution : Update to version 0.9.14.006 or newer

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
include("http_keepalive.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if (! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-5]([^0-9]|$)))", string:matches[1]) )
		security_warning(port);
