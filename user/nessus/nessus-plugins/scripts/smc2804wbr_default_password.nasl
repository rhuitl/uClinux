#
# This script was written by Audun Larsen <larsen@xqus.com>
#


if(description)
{
 script_id(12069);
 script_version("$Revision: 1.4 $");

 name["english"] = "SMC2804WBR Default Password";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is a SMC2804WBR access point.

This host is installed with a default administrator 
password (smcadmin) which has not been modifed.

An attacker may exploit this flaw to gain control over
this host using the default password.


Solution : Change the administrator password
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs in with default password on SMC2804WBR";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Audun Larsen");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if("SMC2804WBR" >< res && "Please enter correct password for Administrator Access. Thank you." >< res)
 {

  host = get_host_name();
  variables = string("page=login&pws=smcadmin");
  req = string("POST /login.htm HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  if("<title>LOGIN</title>" >< buf)
  {
  } else {
   security_hole(port);
   exit(0);
  } 
}

