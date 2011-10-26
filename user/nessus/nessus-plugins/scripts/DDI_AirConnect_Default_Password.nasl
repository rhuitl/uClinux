#
# This script was written by H D Moore
# Information about the AP provided by Brian Caswell
#


if(description)
{
    script_id(10961);
    script_version("$Revision: 1.9 $");
    script_cve_id("CVE-1999-0508");
    name["english"] = "AirConnect Default Password";
    script_name(english:name["english"]);


    desc["english"] = "
    This AirConnect wireless access point still has the 
    default password set for the web interface. This could 
    be abused by an attacker to gain full control over the
    wireless network settings.
    
    Solution:  Change the password to something difficult to
    guess via the web interface.
    
    Risk factor : High";

    script_description(english:desc["english"]);


    summary["english"] = "3Com AirConnect AP Default Password";
    script_summary(english:summary["english"]);


    script_category(ACT_ATTACK);

    script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.",
               francais:"Ce script est Copyright (C) 2002 Digital Defense Inc.");

    family["english"] = "Misc.";
    family["francais"] = "Divers";
    script_family(english:family["english"], francais:family["francais"]);
    script_dependencie("http_version.nasl");
    script_require_keys("Services/www");
    
    exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function sendrequest (request, port)
{
    reply = http_keepalive_send_recv(data:request, port:port);
    if( reply == NULL ) exit(0);
    return(reply);
}

#
# The script code starts here
#


port = get_http_port(default:80);

if(!get_port_state(port)){ exit(0); }

req = string("GET / HTTP/1.0\r\nAuthorization: Basic Y29tY29tY29tOmNvbWNvbWNvbQ==\r\n\r\n");

reply = sendrequest(request:req, port:port);

if ("SecuritySetup.htm" >< reply)
{
    security_warning(port:port);
}
