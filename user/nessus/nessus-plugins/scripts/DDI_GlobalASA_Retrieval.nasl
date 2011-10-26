#
# This script was written by H D Moore
# 


if(description)
{
    script_id(10991);
    script_version ("$Revision: 1.11 $");
    # script_cve_id("CVE-MAP-NOMATCH");
    # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)
    name["english"] = "IIS Global.asa Retrieval";
    script_name(english:name["english"]);


    desc["english"] = "
This host is running the Microsoft IIS web server.  This web server contains 
a configuration flaw that allows the retrieval of the global.asa file.  

This file may contain sensitive information such as database passwords, 
internal addresses, and web application configuration options.  This 
vulnerability may be caused by a missing ISAPI map of the .asa extension 
to asp.dll.

Solution:

    To restore the .asa map:
    
    Open Internet Services Manager. Right-click on the affected web server and choose Properties 
    from the context menu. Select Master Properties, then Select WWW Service --> Edit --> Home 
    Directory --> Configuration. Click the Add button, specify C:\winnt\system32\inetsrv\asp.dll 
    as the executable (may be different depending on your installation), enter .asa as the extension, 
    limit the verbs to GET,HEAD,POST,TRACE, ensure the Script Engine box is checked and click OK.
    
Risk factor : High
";

    script_description(english:desc["english"]);

    summary["english"] = "Tries to retrieve the global.asa file";

    script_summary(english:summary["english"]);


    script_category(ACT_ATTACK);

    script_copyright(english:"This script is Copyright (C) 2001 Digital Defense Inc.");

    family["english"] = "CGI abuses";
    script_family(english:family["english"]);
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

function sendrequest (request, port)
{
    return http_keepalive_send_recv(port:port, data:request);
}

req = http_get(item:"/global.asa", port:port);
reply = sendrequest(request:req, port:port);
if ("RUNAT" >< reply)
{
    security_hole(port:port);
    set_kb_item(name:"iis/global.asa.download", value:TRUE);
}
