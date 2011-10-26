#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# References:
#
# Date: Fri, 23 Aug 2002 09:30:40 +0200 (CEST)
# From: "Wojciech Purczynski" <cliph@isec.pl>
# To: bugtraq@securityfocus.com
# Subject: PHP: Bypass safe_mode and inject ASCII control chars with mail()
# Message-ID:<Pine.LNX.4.44L.0208211118510.23552-100000@isec.pl>
#

if(description)
{
 script_id(10701);
 script_bugtraq_id(2954);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-1246");
 
 name["english"] = "php safemode";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running php 4.0.5.

There is a flaw in this version of PHP that allows
local users to circumvent the safe mode and to gain
the uid of the http process.


Solution : Upgrade to PHP 4.1.0
Risk factor : High";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
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
include("backport.inc");

port = get_http_port(default:80);
banner = get_http_banner(port: port);
if(!banner) exit(0);
php = get_php_version(banner:banner);
if ( ! php ) exit(0);

if(ereg(pattern:"PHP/4\.0\.5.*", string:php))
   security_warning(port);
