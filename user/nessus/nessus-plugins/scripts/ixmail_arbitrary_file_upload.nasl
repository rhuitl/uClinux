#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11781);
 script_bugtraq_id(8046, 8048);
 script_version ("$Revision: 1.7 $");

 
 name["english"] = "iXmail arbitrary file upload";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the iXmail webmail interface.

There is a flaw in this interface which allows an attacker who
has a valid account on this host to upload and execute arbitrary
php files on this host, thus potentially gaining a shell on
this host. An attacker may also use this flaw to delete
arbitrary files on the remote host, with the privileges of the
web server.

Solution : Upgrade to iXMail 0.4
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for iXMail";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);

foreach dir (make_list("/ixmail", cgi_dirs()))
{
 # Ugly.
 req = http_get(item:dir + "/README.TXT", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if("iXmail" >< res) 
 {
  if(egrep(pattern:".*version.*: 0\.[0-3][^0-9]", string:res))
  	{
	security_warning(port);
	exit(0);
	}
 }
}
