#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11345);
 script_bugtraq_id(7045);
 script_version ("$Revision: 1.10 $");

 name["english"] = "SimpleBBS users disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host enumerate its list
of SimpleBBS users by requesting the file users.php.

An attacker may use this flaw to gain the passwords of the users
and impersonate them.

Solution : Disable this CGI
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of users.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/users/users.php"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(ereg(pattern:"^HTTP/.\.. 200 ", string:r) &&
    "username" >< r && 
    egrep(pattern:".*username.*password.*email", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}
