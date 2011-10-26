#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14830);
 script_cve_id("CVE-2004-1554");
 script_bugtraq_id(11260);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:10375);
 script_version ("$Revision: 1.5 $");
 name["english"] = "@lex guestbook remote file include";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running @lex guestbook, a guestbook web application
written in PHP.

This version is prone to a vulnerability that may permit remote attackers, 
without prior authentication, to include and execute malicious PHP scripts. 
Remote users may influence URI variables to include a malicious PHP script 
on a remote system, it is possible to cause arbitrary PHP code to be executed. 

Solution : Update to the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for @lex guestbook";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

function check(dir)
{
	req = http_get(item:dir + "/livre_include.php?no_connect=lol&chem_absolu=http://xxxxxx./", port:port);

	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);

	if ("http://xxxxxx./config/config" >< r )
	{ 
 			security_hole(port);
			exit(0);
    	}
 
}

foreach dir (cgi_dirs())
{
 check(dir:dir);
}
