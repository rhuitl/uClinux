#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Oliver Karow
# 
#  This script is released under the GNU GPLv2
#

if(description)
{
 script_id(19946);
 script_bugtraq_id(9039, 13037); 
 script_version ("$Revision: 1.1 $");

 name["english"] = "WebWasher < 4.4.1 Build 1613 Multiple Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote web proxy suffers from multiple flaws.

Description : 

The remote host is running the web proxy WebWasher.

According to its banner, the installed version of WebWasher is prone to
multiple cross-site scripting flaws.  Successful exploitation of these
issues may allow an attacker to execute malicious script code in a
user's browser within the context of the affected website. 

See also :

http://www.oliverkarow.de/research/WebWasherXSS.txt
http://www.oliverkarow.de/research/wwcsm.txt

Solution : 

Upgrade to WebWasher CSM 4.4.1 Build 1613 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of WebWasher Proxy";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080, 9090);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:9090);

if(!get_port_state(port))exit(0);

req = http_get(item:"/nessus345678.html", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
if( r == NULL )exit(0);

if ( ("<title>WebWasher - " >< r))
{
 if (egrep(pattern:"generated .* by .* \(WebWasher ([0-3]\..*|4\.([0-3] .*|4\.1 .uild ([0-9][0-9][0-9]|1([0-5][0-9][0-9]|6(0[0-9]|1[0-2])))))\)", string:r))
 {
   security_note(port);
   exit(0);
 }
}
