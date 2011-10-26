#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: PhpGroupWare Team
# This script is released under the GNU GPLv2


if(description)
{
 script_id(14295);
 script_bugtraq_id(9387);
 script_version ("$Revision: 1.7 $");
  if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"6860");
 script_cve_id("CVE-2004-0016");
 name["english"] = "PhpGroupWare calendar server side script execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of PhpGroupware which is vulnerable
to a remote attack.

PhpGroupWare is a multi-user groupware suite written in PHP.

It has been reported that this version may be prone to a vulnerability that 
may allow remote attackers to execute malicious scripts on a vulnerable system. 
The flaw allows remote attackers to upload server side scripts which can then 
be executed on the server.

Solution : Update to version 0.9.14.007 or newer

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
if (! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-6]([^0-9]|$)))", string:matches[1]) )
 			security_warning(port);
