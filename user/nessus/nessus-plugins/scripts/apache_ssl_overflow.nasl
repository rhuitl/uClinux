#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>,
# with the impulsion of H D Moore on the Nessus Plugins-Writers list
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10918);
 script_bugtraq_id(4189);
 script_cve_id("CVE-2002-0082");
 script_version("$Revision: 1.11 $");
 
 name["english"] = "Apache-SSL overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of Apache-SSL which is
older than 1.47

This version is vulnerable to a buffer overflow which,
albeit difficult to exploit, may allow an attacker
to obtain a shell on this host.


Solution : Upgrade to version 1.47 or newer
Risk factor : High";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of Apache-SSL";
 summary["francais"] = "Vérifie la version de Apache-SSL";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include ("http_func.inc");
include ("backport.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_backport_banner(banner:get_http_banner(port: port));
 
 serv = strstr(banner, "Server");
 if(ereg(pattern:".*Apache(-AdvancedExtranetServer)?/.* Ben-SSL/1\.([0-9][^0-9]|[0-3][0-9]|4[0-6])[^0-9]", string:serv))
 {
   security_warning(port);
 }
}
