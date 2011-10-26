#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10291);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0177");
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"229");
 }
 name["english"] = "uploader.exe";
 name["francais"] = "uploader.exe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
command execution. 

Description :

The remote web server contains a CGI script named 'uploader.exe' in
'/cgi-win'.  Versions of O'Reilly's Website product before 1.1g
included a script with this name that allows an attacker to upload
arbitrary CGI and then execute them. 

See also :

http://www.nessus.org/u?4b667852
http://www.nessus.org/u?3bca098f

Solution : 

Verify that the affected script does not allow arbitrary uploads and
remove it if it does. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /cgi-win/uploader.exe";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
cgi = "/cgi-win/uploader.exe";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);

