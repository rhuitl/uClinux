#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15772);
 script_cve_id("CVE-2004-2469");
 script_bugtraq_id(11690);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "phpScheduleIt Unspecified Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpScheduleIt, a web-based reservation system
written in PHP.

According to its banner, this version is reported vulnerable to an undisclosed
issue which may allow an attacker to modify or delete phpScheduleIt
reservations.

Solution : Upgrade to the latest version of this software
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a vulnerability in phpScheduleIt";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("phpscheduleit_xss.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/phpScheduleIt");
if ( ! kb ) exit(0);
match = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^(0\.|1\.0\.0)", string:match[1]) ) 
	security_warning( port );
