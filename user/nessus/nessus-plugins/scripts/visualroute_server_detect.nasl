#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis : 

A VisualRoute server is listening on the remote port.

Description :

VisualRoute is a web based solution which allows unauthenticated
users to peform traceroutes against arbitrary hosts on the internet.

Solution : 

Disable this service if you do not use it.

Risk factor : 

None";
if(description)
{
 script_id(10744);
 script_version ("$Revision: 1.9 $");

 name["english"] = "VisualRoute Web Server Detection";
 script_name(english:name["english"]);


 script_description(english:desc["english"]);

 summary["english"] = "Extracts the banner of  the remote visual route server";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);

 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
req = http_get(item:"/", port:port);
soc = http_open_socket(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
res = http_recv(socket:soc);
close(soc);
if ( res == NULL ) exit(0);

if ( res =  egrep(pattern:"^Server: VisualRoute", string:res) )
 {
  version = chomp(res);
  version -= "Server : ";
  report = desc["english"] + '\n\nPlugin output :\n\nThe remote version of VisualRoute is ' + res;
  security_note(port:port, data:report);
  set_kb_item(name:"www/" + port + "/embedded", value:TRUE);
 }
