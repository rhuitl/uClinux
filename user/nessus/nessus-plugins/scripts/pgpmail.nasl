#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added CAN.  Added link to the Bugtraq message archive
#
# GPL
#
# References:
# From: joetesta@hushmail.com
# To: bugtraq@securityfocus.com, jscimone@cc.gatech.edu
# Subject: Vulnerabilities in PGPMail.pl
# Date: Thu, 29 Nov 2001 19:45:38 -0800
# 
# John Scimone <jscimone@cc.gatech.edu>.  
# <http://www.securityfocus.com/archive/82/243262>
#

if(description)
{
 script_id(11070);
 script_bugtraq_id(3605);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2001-0937");
 
 name["english"] = "PGPMail.pl detection";
 script_name(english:name["english"]);
 
 desc["english"] = "The 'PGPMail.pl' CGI is installed. 
Some versions (up to v1.31 a least) of this CGI do not
properly filter user input before using it inside commands.
This would allow a cracker to run any command on your server.

*** Note: Nessus just checked the presence of this CGI 
*** but did not try to exploit the flaws.
 
Solution : remove it from /cgi-bin or upgrade it.

Reference : http://online.securityfocus.com/archive/82/243262
Reference : http://online.securityfocus.com/archive/1/243408

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of PGPMail.pl";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"PGPMail.pl");
if(res) security_warning(port);

