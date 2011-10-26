#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11569);
 script_bugtraq_id(7485);
 script_version ("$Revision: 1.6 $");

 name["english"] = "StockMan Shopping Cart Command Execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the StockMan shopping cart.

According to the version number of the CGI 'shop.plx, there is
a flaw in this installation which may allow an attacker to
execute arbitrary commands on this host, and which may even
allow him to obtain your list of customers or their credit
card number.


Solution : upgrade to StockMan Shopping Cart Version 7.9 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "determines the version of shop.plx";
 
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
 req = http_get(item:string(loc, "/shop.plx"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"Stockman Shopping Cart Version ([0-6]\.|7\.[0-8])", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
