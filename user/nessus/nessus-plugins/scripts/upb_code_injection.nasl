# 
# (C) Tenable Network Security
#
#


if(description)
{
 script_id(11671);
 script_bugtraq_id(7678);
 script_version ("$Revision: 1.6 $");

 
 name["english"] = "Ultimate PHP Board admin_ip.php code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Ultimate PHP Board (UPB).

There is a flaw in this version which may allow an attacker
to execute arbitrary code on this host, by sending a malformed
user-agent which contains PHP commands.  Once the user-agent
has been sent, it is stored in the logs. When the administrator
of this web site will read the logs through admin_ip.php,
the code will be executed.

Solution : Upgrade to the latest version of this CGI 
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for UPB";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach d (make_list( "/upb", "/board", cgi_dirs()))
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(egrep(pattern:"Powered by<br>UPB Version :.* 1\.(0[^0-9]|[0-9])", string:res))
   {
 	security_hole(port);
	exit(0);
 }
}
