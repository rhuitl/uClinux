# This script was written by Michel Arboi <arboi@alussinan.org> 
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# Date:  Mon, 11 Mar 2002 12:46:06 +0700
# From: "Fyodor" <fyarochkin@trusecure.com>
# To: bugtraq@securityfocus.com
# Subject: SunSolve CD cgi scripts...
#
# Date: Sat, 16 Jun 2001 23:24:45 +0700
# From: Fyodor <fyodor@relaygroup.com>
# To: security-alert@sun.com
# Subject: SunSolve CD security problems..
#

if(description)
{
 script_id(11066);
 script_bugtraq_id(4269);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2002-0436");

 name["english"] = "SunSolve CD CGI user input validation";
 script_name(english:name["english"]);
 
 desc["english"] = "
Sunsolve CD CGI scripts does not validate user input.
Crackers may use them to execute some commands on your system.

** Note: Nessus did not try to perform the attack.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "SunSolve CD CGI scripts are vulnerable to a few user input validation problems";
 
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 8383);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:8383);

if (is_cgi_installed_ka(port: port, item:"/cd-cgi/sscd_suncourier.pl")) {
	security_warning(port);
	exit(0);
}

if (is_cgi_installed_ka(port: port, item:"sscd_suncourier.pl")) {
	security_warning(port);
	exit(0);
}
