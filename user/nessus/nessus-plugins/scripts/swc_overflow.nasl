#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive and Securiteam
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10493);
 script_version ("$Revision: 1.17 $");
 
 name["english"] = "SWC Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The CGI 'swc' (Simple Web Counter) is present and vulnerable
to a buffer overflow when issued a too long value to the
'ctr=' argument.

An attacker may use this flaw to gain a shell on this host

Solution : Use another web counter, or patch this one by hand

Reference : http://online.securityfocus.com/archive/1/76818

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/swc";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir, "/swc?ctr=", crap(500)),
 	        port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 
 if("Could not open input file" >< r)
 {
   soc = http_open_socket(port);
   req = http_get(item:string(dir, "/swc?ctr=", crap(5000)), port:port);
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   http_close_socket(soc);
   if(ereg(pattern:"HTTP/[0-9]\.[0-9] 500 ", 
	   string:r))security_hole(port);
 }
}
