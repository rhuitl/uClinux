#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#
#
# Modifications by Tenable :
#
# - Description
#
# Modifications by Daniel Reich <me at danielreich dot com>
#
# - Added detection for HP Remote Insight ILO Edition II
# - Removed &copy; in original string, some versions flip the 
#   order of Copyright and &copy;
# - Revision 1.2
#

if(description)
{
script_id(20285);

script_version("$Revision: 1.2 $");
script_name(english:"HP Integrated Lights-Out Detection");

desc["english"] = "
Synopsis :

The remote host is an HP Integrated Lights-Out console.

Description :

The remote host is running HP Integrated Lights Out (iLO), a remote
server management software that is integrated into HP ProLiant
servers.

Solution :

Filter incoming traffic to this port if you do not use it

Risk factor :

None";

script_description(english:desc["english"]);
script_summary(english:"Detects iLO");

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_family(english:"General");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port))exit(0);

buf = http_get(item:"/login.htm", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
if(
  ("<TITLE>HP Integrated Lights-Out Login<" >< r &&
  egrep(pattern:"Copyright .+ Hewlett-Packard Development Company", string:r)) ||
  ("<title>HP Remote Insight<" >< r &&
  egrep(pattern:"Hewlett-Packard Development Company", string:r) )

) 
     security_note(port);
  
