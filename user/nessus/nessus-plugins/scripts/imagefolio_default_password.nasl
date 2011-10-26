#
# (C) Tenable Network Security
#
# Ref: 
#  From: "Paul Craig" <pimp@brainwave.net.nz>
#  To: <bugtraq@securityfocus.com>
#  Subject: ImageFolio All Versions      (...)
#  Date: Thu, 5 Jun 2003 13:53:57 +1200


if(description)
{
 script_id(11700);

 script_version("$Revision: 1.5 $");
 name["english"] = "ImageFolio Default Password";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the ImageFolio image gallery manager.

This CGI is installed with a default administrator username and
password (Admin/ImageFolio) which has not been modifed.

An attacker may exploit this flaw to administrate this installation.

In addition to this, the CGI admin.cgi has a bug which may allow
an attacker to delete arbitrary files owned by the remote web server.

Solution : Change the administrator password
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs in as Admin/ImageFolio";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(req)
{
  host = get_host_name();
  variables = string("login=1&user=Admin&password=ImageFolio&save=Login");
  req = string("POST ", req, " HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  if("<title>My ImageFolio Gallery Administration : </title>" >< buf)
  {
   security_hole(port);
   exit(0);
  }
 
 
 return(0);
}

port = get_http_port(default:80);



foreach dir (cgi_dirs())
{
 check(req:dir + "/admin/admin.cgi");
 exit(0);
}
