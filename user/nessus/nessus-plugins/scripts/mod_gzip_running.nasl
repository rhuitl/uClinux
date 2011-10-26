#
# (C) Tenable Network Security

if(description)
{
 script_id(11685);
 
 script_version("$Revision: 1.4 $");
 name["english"] = "mod_gzip running";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running mod_gzip whose status can be 
obtained by requesting /mod_gzip_status.


If you do not use this module, disable it completely.

Solution : Change the directive 'mod_gzip_command_version' to something secret
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "mod_gzip detection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");



 
port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


req = http_get(item:"/mod_gzip_status", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("mod_gzip_version" >< res)
{
	security_note(port);
}
