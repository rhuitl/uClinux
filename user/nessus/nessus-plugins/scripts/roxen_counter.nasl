#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#
# Minor changes by rd :
#
# - check for the error code in the first line only
# - compatible with no404.nasl
#
if(description)
{
 script_id(10207);
 script_version ("$Revision: 1.15 $");
 name["english"] = "Roxen counter module";
 script_name(english:name["english"]);
 
 desc["english"] = "The Roxen Challenger webserver is running and the counter module is installed.
Requesting large counter GIFs eats up CPU-time on the server. If the server does not support threads this will prevent the server from serving other clients.

Solution : Disable the counter-module. There might be a patch available in the future. 

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Roxen counter module installed ?";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Hendrik Scholz");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner || "Roxen" >!< banner ) exit(0);

if(get_port_state(port) && ! get_kb_item("Services/www/" + port + "/embedded") )
{
 name = string("www/no404/", port);
 no404 = tolower(get_kb_item(name));
 data = string("/counter/1/n/n/0/3/5/0/a/123.gif");
 data = http_get(item:data, port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  line = recv_line(socket:soc, length:1024);
  buf = http_recv(socket:soc);
  buf = tolower(buf);
  must_see = "image";
  http_close_socket(soc);
  if(no404)
  {
    if(no404 >< buf)exit(0);
  }
  if((" 200 " >< line)&&(must_see >< buf))security_warning(port);
 }
}

