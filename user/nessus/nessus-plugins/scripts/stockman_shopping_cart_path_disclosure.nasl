#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11568);
 script_version ("$Revision: 1.6 $");

 name["english"] = "StockMan Shopping Cart Path disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the StockMan shopping cart.

There is a flaw in this version which may allow an attacker to obtain
the physical path to the remote web root by requesting a non-exisant
page through the 'shop.plx' CGI.

An attacker may use this flaw to gain more knowledge about the setup
of the remote host.

Solution : upgrade to StockMan Shopping Cart Version 7.9 or newer
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "determines the remote root path";
 
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



function check(loc)
{
 req = http_get(item:string(loc, "/shop.plx/page=nessus"+rand()),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*Error opening HTML file: /.*/nessus", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
