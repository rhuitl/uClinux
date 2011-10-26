#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10304);
 script_bugtraq_id(969);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0127");
 
 name["english"] = "WebSpeed remote configuration";
 name["francais"] = "configuration a distance de WebSpeed";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an application that is prone to privilege
escalation attacks. 

Description :

The remote web server appears to be using Webspeed, a website creation
language used with database-driven websites. 

The version of Webspeed installed on the remote host allows anonymous
access to the 'WSMadmin' utility, which is used configure Webspeed.  An
attacker can exploit this issue to gain control of the affected
application. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2000-02/0013.html	
	
Solution : 

Edit the 'ubroker.properties' file and change 'AllowMsngrCmds=1' to
'AllowMsngrCmds=0'. 
	
Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if webspeed can be administered";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
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

cgi = "/scripts/wsisa.dll/WService=anything?WSMadmin";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
 


