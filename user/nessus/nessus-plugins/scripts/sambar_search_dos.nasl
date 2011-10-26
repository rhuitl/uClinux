#
# written by Gareth Phillips - SensePost (www.sensepost.com)
# Released under GPLv2
#
# changes by Tenable:
# - Longer regex to match on
# - Also match on the server version number
#
#
if(description)
{
 script_id(18650);
 script_bugtraq_id (7975);
 script_version ("$Revision: 1.2 $");


 name["english"] = "Sambar Search Results Buffer Overflow Denial of Service";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Sambar Server, a web server package.

The remote version of this software contains a flaw that may allow an attacker 
to crash the service remotely.

A buffer overflow was found in the /search/results.stm application that 
comes shipped with Sambar Server. 

Vulnerable versions: Sambar Server 4.x
		     Sambar Server 5.x
		     Sambar Server 6.0

Solution: Upgrade to current release of this software
Risk factor : High";
 script_description(english:desc["english"]);

 summary["english"] = "Sambar Search Results Buffer Overflow DoS";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 SensePost");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Code Starts Here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port || ! get_port_state(port) ) exit(0);

req = http_get(item:"/search/results.stm", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if ( egrep(pattern:"^Server: Sambar (4\.|5\.[01]([^0-9]|$))", string:res, icase:TRUE) )
  security_hole (port);
else if ( egrep(pattern:"&copy; 1997-(199[8-9]|200[0-3]) Sambar Technologies, Inc. All rights reserved.", string:res) ) 
  security_hole (port);

