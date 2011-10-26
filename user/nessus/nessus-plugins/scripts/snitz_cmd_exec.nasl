#
# (C) Tenable Network Security
#

if (description)
{
 script_id(11621);
 script_version ("$Revision: 1.6 $");

 script_name(english:"Snitz Forums Cmd execution");
 desc["english"] = "
The remote host is using Snitz Forum 2000

This set of CGI is vulnerable to a SQL injection issue
that may allow attackers to gain the control of the remote
database and even execute arbitary commands on this host.

Solution: Upgrade to a newer version.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if Snitz forums is vulnerable to a cmd exec flaw");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


function mkreq(path)
{
 data = "Refer=&Email=test%27example.org&Email2=&HideMail=0&ICQ=&YAHOO=&AIM=&Homepage=&Link1=&Link2=&Name=test&Password=test&Password-d=&Country=&Sig=&MEMBER_ID=&Submit1=Submit";
 req = string("POST ", path, "/register.asp?mode=DoIt HTTP/1.1\r
Host: ", get_host_name(), "\r
User-Agent: Mozilla/5.0 (X11; U; Linux i386; en-US; rv:1.3)\r
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,video/x-mng,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r
Accept-Language: en-us,en;q=0.5\r
Accept-Encoding: gzip,deflate,compress;q=0.9\r
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r
Referer: http:/", get_host_name(), path, "/register.asp\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: ", strlen(data), "\r\n\r\n", data);
 return req;
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);


		


foreach d ( cgi_dirs() )
{
 if ( is_cgi_installed_ka(item:d + "/register.asp", port:port) )
 {
 req = mkreq(path:d);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("HTTP/1.1 500" >< res && "Microsoft OLE DB Provider for SQL Server" >< res){ security_hole(port); exit(0); }
 }
}
