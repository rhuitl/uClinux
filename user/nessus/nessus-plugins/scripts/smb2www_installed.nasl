if(description)
{
 script_id(11377);
 script_version("$Revision: 1.3 $");
 
 
 
 name["english"] = "smb2www installed";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running smb2www - a SMB to WWW gateway.

An attacker may use this CGI to use this host as a proxy - 
he can connect to third parties SMB host without revealing
his IP address.

Solution : Enforce proper access controls to this CGI
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "smb2www Command Execution";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
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

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = make_list("/samba");

foreach d (cgi_dirs())
{ 
 dirs = make_list(dirs, d, string(d, "/samba"));
}

foreach d (dirs)
{
 req = http_get(item:string(d, "/smb2www.pl"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if("Welcome to the SMB to WWW gateway" >< res){
 	security_warning(port);
	exit(0);
	}
}

