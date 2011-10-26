#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19218);
 script_bugtraq_id(14287);
 script_version("$Revision: 1.2 $");
 name["english"] = "Sybase EAServer Default Administrator password";
 script_name(english:name["english"]);
 
 desc["english"] = "
This host appears to be the running the Sybase EAServer Management
with the default administrator accounts still configured (jagadmin/'').
A potential intruder could reconfigure this service in a way that grants
system access.

Solution : Change default administrator password.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for default administrator password in Sybase EAServer";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
 req = http_get(item:string(dir, "/Login.jsp"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ("Sybase Management Console Login" >< r  )
 {
  host = get_host_name();
  variables = "j_username=jagadmin&j_password=&submit.x=29&submit.y=10&submit=login";
  req = string("POST ", dir, "/j_security_check HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("Set-Cookie: JAGID=" >< buf)
  {
   security_hole(port);
   exit(0);
  }
 }

 return(0);
}

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);
banner = get_http_banner (port:port);
if ("Server: Jaguar Server Version" >!< banner)
  exit (0);


foreach dir (make_list(cgi_dirs(), "/WebConsole")) 
{
 check(dir:dir);
}
