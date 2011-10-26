#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Date: Thu, 9 Jan 2003 00:50:48 +0200 (EET)
# From: Jouko Pynnonen <jouko@solutions.fi>
# To: <vulnwatch@vulnwatch.org>
# Subject: [VulnWatch] IMP 2.x SQL injection vulnerabilities

if(description)
{
 script_id(11488);
 script_version ("$Revision: 1.5 $");
 
 

 
 name["english"] = "IMP SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running IMP.

There is a bug in this release which allow an attacker to perform
an SQL injection attack by requesting :
/imp/mailbox.php3?actionID=6&server=x&imapuser=x'&pass=x

An attacker may use this flaw to gain unauthorized access to a user
mailbox or to take the control of the remote database.

Solution : Upgrade to the latest version
Risk factor : High";





 script_description(english:desc["english"]);
 
 summary["english"] = "Checks IMP version";
 
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

if ( ! can_host_php(port:port) ) exit(0);


dirs = make_list(cgi_dirs(), "/imp", "/horde/imp");

foreach d (dirs)
{
 req = http_get(item:string(d, "/mailbox.php3?actionID=6&server=x&imapuser=x';somesql&pass=x"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if('parse error at or near "somesql"' >< res ) {
 	 security_hole(port);
	 exit(0);
	 }
}
