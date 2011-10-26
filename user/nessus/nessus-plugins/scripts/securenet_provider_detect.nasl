#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18533);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Intrusion.com SecureNet provider detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to run the Intrusion.com SecureNet provider on this port.
Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Intrusion.com SecureNet provider console";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("httpver.nasl");
 script_require_ports(80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = 80;
if(get_port_state(port))
{
 rep = http_get_cache(item:"/", port:port);
 if( rep == NULL ) exit(0);
 if(" - SecureNet Provider WBI</title>" >< rep)
 {
   security_note(port);
   set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
}
