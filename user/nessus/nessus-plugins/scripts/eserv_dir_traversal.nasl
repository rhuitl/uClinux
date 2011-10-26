#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
# Date: Wed, 21 May 2003 19:40:00 -0700
# From: D4rkGr3y <grey_1999@mail.ru>
# To: bugtraq@security.nnov.ru, bugtraq@securityfocus.com
# Subject: EServ/2.99: problems


if(description)
{
 script_id(11656);
 script_bugtraq_id(7669);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Eserv Directory Index";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to get the list of the files in
the remote web root by sending a specially malformed
GET request to this server.

An attacker may use this flaw to get the list
of supposedly hidden files stored on this
web server.

Solution : None at this time
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "GET /?";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if('a href="./"' >< res && 'a href="../"' >< res)exit(0);
 
 
req = http_get(item:"/?", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if('a href="./"' >< res && 'a href="../"' >< res)security_warning(port);
