#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10365);
 script_bugtraq_id(1073);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0242"); 
 name["english"] = "Windmail.exe allows any user to execute arbitrary commands";
 name["francais"] = "Windmail.exe allows any user to execute arbitrary comands";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
command execution. 

Description :

The remote host may be running WindMail as a CGI application.  In this
mode, some versions of the 'windmail.exe' script allow an attacker to
execute arbitrary commands on the remote server. 

See also : 

http://seclists.org/lists/bugtraq/2000/Mar/0322.html

Solution : 

Remove the CGI script.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of windmail.exe";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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
banner = get_http_banner(port:port);
if ( ! banner || "Server: Microsoft/IIS" >!< banner ) exit(0);

res = is_cgi_installed_ka(item:"windmail.exe", port:port);
if(res)security_hole(port);
