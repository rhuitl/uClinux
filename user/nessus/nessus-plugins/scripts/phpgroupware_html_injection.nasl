#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: François SORIN <francois.sorin@security-corporation.com>
# This script is released under the GNU GPLv2


if(description)
{
 script_id(14292);
 script_bugtraq_id(8088);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2003-0504");
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"2243");
 name["english"] = "PhpGroupWare multiple HTML injection vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running PhpGroupWare, is a multi-user groupware 
suite written in PHP.

This version has been reported prone to multiple HTML injection vulnerabilities. 
The issues present themselves due to a lack of sufficient input validation 
performed on form fields used by PHPGroupWare modules. 

A malicious attacker may inject arbitrary HTML and script code using these 
form fields that may be incorporated into dynamically generated web content.

Solution : Update to version 0.9.14.005 or newer

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
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-3]([^0-9]|$)))", string:matches[1]))
 			security_warning(port);
