#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
#  Date: Mon, 14 Apr 2003 12:34:54 -0400
#  From: Jim Dew <jdew@cleannorth.org>
#  To: bugtraq@securityfocus.com
#  Subject: Instaboard 1.3 SQL Injection

if(description)
{
 script_id(11532);
 script_bugtraq_id(7338);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Instaboard SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running NetPleasure's Instaboard.

There is a bug in this release which allow an attacker to perform
an SQL injection attack through the page 'index.cfm'.

An attacker may use this flaw to gain unauthorized access to take
the control of the remote database.

Solution : Upgrade to the latest version
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SQL insertion in Instaboad";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


dirs = make_list(cgi_dirs(), "/instaboard");

foreach d (dirs)
{
 req = http_get(item:string(d, "/index.cfm?catid=1%20SQL"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("[Microsoft][ODBC SQL Server Driver][SQL Server]" >< res)
	{
 	 security_hole(port);
	 exit(0);
	 }
}
