#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11581);
 script_bugtraq_id(7444);
 script_version ("$Revision: 1.7 $");

 name["english"] = "album.pl Command Execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the CGI 'album.pl' which
is older than version 6.2

According to its version number, this CGI may allow an attacker
to execute arbitrary commands on this host with the privileges of the
HTTP daemon.

Solution : upgrade to album.pl version 6.2.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "determines the version of album.pl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
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



function check(loc)
{
 req = http_get(item:string(loc, "/album.pl?function=about"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"album.pl V([0-5]|6\.[01]([^0-9]|$))", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dirs = make_list(cgi_dirs());
foreach dir (dirs)
{
 check(loc:dir);
}
