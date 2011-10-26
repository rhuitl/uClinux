# By John Lampe ... j_lampe@bellsouth.net
#
# changes by rd: code of the plugin checks for a valid tag in the reply

if (description)
{
 script_id(11657);
 script_version ("$Revision: 1.4 $");

 script_name(english:"Synchrologic User account information disclosure");
 desc["english"] = "
The remote host seems to be running Synchrologic Email Accelerator

Synchrologic is a product which allows remote PDA users to synch with email,
calendar, etc.

If this server is on an Internet segment (as opposed to internal), you may
wish to tighten the access to the aggregate.asp page.

The server allows anonymous users to look at Top Network user IDs
Example : http://IP_ADDRESS/en/admin/aggregate.asp

Risk factor : Low";



 script_description(english:desc["english"]);
 script_summary(english:"Determines if Synchrologic is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

req = http_get(item:"/en/admin/aggregate.asp", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if("/css/rsg_admin_nav.css" >< res)
	security_warning(port);
