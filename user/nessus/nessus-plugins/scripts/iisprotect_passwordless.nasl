#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
#


if(description)
{
 script_id(11661);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "Unpassworded iiprotect administrative interface";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running iisprotect, an IIS add-on to protect the
pages served by this server.

However, the administration module of this interface has not been
password protected. As a result, an attacker may perform administrative
tasks without any authentication.

Solution : Set a password for this page
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if iisprotect is password-protected";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


if(get_port_state(port))
{
 req = http_get(item:"/iisprotect/admin/GlobalAdmin.asp?V_FirstTab=GlobalSetting", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<form action='/iisprotect/admin/GlobalAdmin.asp' method='POST'>" >< res)security_hole(port);
}
