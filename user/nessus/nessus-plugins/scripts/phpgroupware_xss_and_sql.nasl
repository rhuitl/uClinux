#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15983);
 script_cve_id("CVE-2004-1383", "CVE-2004-1384");
 script_bugtraq_id(11952);
 script_version ("$Revision: 1.5 $");
 name["english"] = "PhpGroupWare XSS and SQL injection issues";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running PhpGroupWare, is a multi-user
groupware suite written in PHP. 

The remote version of this software is vulnerable to two issues :

- A cross site scripting issue may allow an attacker to steal the
credentials of third-party users of the remote host ;

- A SQL injection vulnerability may allow an attacker to execute
arbitrary SQL statements against the remote database. 

Solution : Update to the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of phpGroupWare";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8][^0-9]|9\.([0-9][^0-9]|1([0-5][^0-9]|6\.(00[0-3]|RC[0-9]))))", string:matches[1]))
	security_warning(port);
