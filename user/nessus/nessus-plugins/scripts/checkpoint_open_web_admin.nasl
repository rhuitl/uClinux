#
# This script was written by Matthew North < matthewnorth@yahoo.com >
#
# Checks to see if remote Checkpoint Firewall is open to Web administration.
# If it is open to web administration, then a brute force password attack 
# against the Firewall can be launch.
#
#
# Changes by rd: Description and usage of the http_func functions.
#

if(description)
{
 script_id(11518);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Checkpoint Firewall open Web adminstration";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Checkpoint Firewall is open to Web administration.

An attacker use it to launch a brute force password attack
against the firewall, and eventually take control of it.

Solution : Disable remote Web administration or filter packets going to this port
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote Checkpoint Firewall is open to Web adminstration";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Matthew North");
 family["english"] = "Firewalls";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
res = http_get_cache(port:port, item:"/");
if (res != NULL ) {
    if("ConfigToolPassword" >< res) {
           security_warning(port);
    }
}
