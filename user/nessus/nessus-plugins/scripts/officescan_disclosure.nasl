#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# References :
# Date:  Tue, 16 Oct 2001 11:34:56 +0900
# From: "snsadv@lac.co.jp" <snsadv@lac.co.jp>
# To: bugtraq@securityfocus.com
# Subject: [SNS Advisory No.44] Trend Micro OfficeScan Corporate Edition
# (Virus Buster Corporate Edition) Configuration File Disclosure Vulnerability 
#

if(description)
{
 script_id(11074);
 script_bugtraq_id(3438);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "OfficeScan configuration file disclosure";
 name["francais"] = "OfficeScan révèle son fichier de configuration";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Trend Micro OfficeScan Corporate Edition (Japanese version: Virus 
Buster Corporate Edition) web-based management console let anybody 
access /officescan/hotdownload without authentication.

Reading the configuration file /officescan/hotdownload/ofcscan.ini
will reveal information on your system. More, it contains passwords
that are encrypted by a weak specific algorithm; so they might be 
decrypted

Solution :  upgrade OfficeScan
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /officescan/hotdownload/ofscan.ini";
 summary["francais"] = "Vérifie la présence de /officescan/hotdownload/ofscan.ini";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencie("http_version.nasl");
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"/officescan/hotdownload/ofscan.ini");
if(res)
{
 res = is_cgi_installed_ka(port:port, item:"/officescan/hotdownload/nessus.ini");
 if ( res ) exit(0);
 security_hole(port);
}
