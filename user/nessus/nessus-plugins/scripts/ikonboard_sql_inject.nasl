#
# (C) Tenable Network Security
# 

if(description)
{
 script_id(15986);
 script_cve_id("CVE-2004-1406");
 script_bugtraq_id(11982);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "IkonBoard SQL injection vulnerabilties";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running IkonBoard, a Web Bulletin Board System
written in Perl.

The remote version of this software is vulnerable to several SQL injection
vulnerabilities which may allow an attacker to insert arbritrary SQL
statements in the remote database.

Solution : Upgrade to the latest version of this CGI.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Ikonboard.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


foreach d (cgi_dirs())
{
 req = http_get(item:d+"/ikonboard.cgi?act=ST&f=1&t=1&hl=nessus&st='", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "SELECT * FROM ib_forum_posts WHERE TOPIC_ID = '1' AND QUEUED <> '1' ORDER BY POST_DATE ASC LIMIT" >< res )
	{
	security_hole(port);
	exit(0);
	}
}
