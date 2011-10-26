#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14196);
 script_bugtraq_id(10721);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "4D WebStar Information Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running 4D WebStar Web Server.

The remote server is vulnerable to two issues :

- An attacker may be able to obtain the listing of a directory by appending
a star (*) to the directory name

- An attacker may obtain the file php.ini by requesting /cgi-bin/php.ini

Solution : Upgrade to 4D WebStar 5.3.3 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for 4D WebStar";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same port
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:banner) ) 
{
 req = http_get(item:"/cgi-bin/php.ini", port:port);
 res = http_keepalive_send_recv(port:port, data:req, embedded:TRUE);
 if ( res == NULL ) exit(0);
 if ( "safe_mode" >< res || "http://php.net/manual/" >< res )
	security_warning(port);
}
