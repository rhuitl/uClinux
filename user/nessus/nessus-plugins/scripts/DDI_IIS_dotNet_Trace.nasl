#
# This script was written by H D Moore
# 


if(description)
{
    script_id(10993);
    script_version ("$Revision: 1.8 $");
    name["english"] = "IIS ASP.NET Application Trace Enabled";
    script_name(english:name["english"]);


    desc["english"] = "
The ASP.NET web application running in the root
directory of this web server has application
tracing enabled. This would allow an attacker to
view the last 50 web requests made to this server,
including sensitive information like Session ID values
and the physical path to the requested file.

Solution: Set <trace enabled=false> in web.config

Risk factor : High
";

    script_description(english:desc["english"]);

    summary["english"] = "Checks for ASP.NET application tracing";
    script_summary(english:summary["english"]);


    script_category(ACT_ATTACK);

    script_copyright( english:"This script is Copyright (C) 2002 Digital Defense Inc.",
                      francais:"Ce script est Copyright (C) 2002 Digital Defense Inc.");

    family["english"] = "CGI abuses";
    family["francais"] = "Abus de CGI";

    script_family(english:family["english"], francais:family["francais"]);
    script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
    script_require_ports("Services/www", 80);
    exit(0);
}


#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){ exit(0); }
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);


req = http_get(item:"/trace.axd", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ("Application Trace" >< res)
{
    security_hole(port:port);
}
