#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15614);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "CheckPoint InterSpect";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running CheckPoint InterSpect,
an internet security gateway. 

The Nessus host is liked to have been put in quarantine, 
its activity will be dropped for 30 minutes by default.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect CheckPoint InterSpect";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("httpver.nasl");
 script_require_ports(80,3128);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

r = http_get_cache(item:"/", port:port);
if( r == NULL )exit(0);
if (egrep(pattern:"<TITLE>Check Point InterSpect - Quarantine</TITLE>.*Check Point InterSpect", string:r))
   {
    security_note(port);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
   }
