#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15931);
 script_cve_id("CVE-2004-1223");
 script_bugtraq_id(11869);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "F-Secure Policy Manager Path Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running F-Secure Policy Manager, a distributed 
administration software allowing a system administrator to control applications
from a single web console.

There is a flaw in the file '/fsms/fsmsh.dll' which discloses the physical path
this application is under. An attacker may use the knowledge gained thru
this problem to set up more accurate elaborated attacks against the remote
host.

Solution : Upgrade to the newer version of this CGI
Risk factor : Low";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for /fsms/fsmsh.dll";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

res = http_keepalive_send_recv(port:port, data:http_get(item:"/fsms/fsmsh.dll?", port:port), bodyonly:1);
if ( res == NULL ) exit(0);
if ( "Commdir path" >< res )
{
report = "
The remote host is running F-Secure Policy Manager, a distributed 
administration software allowing a system administrator to control applications
from a single web console.

There is a flaw in the file '/fsms/fsmsh.dll' which discloses the physical path
this application is under. An attacker may use the knowledge gained thru
this problem to set up more accurate elaborated attacks against the remote
host.

By requesting '/fsms/fsmsh.dll?', an attacker can obtain the following
information :
" + res + "

Solution : Upgrade to the newer version of this CGI
Risk factor : Low";

 security_note(port:port, data:report);
}
