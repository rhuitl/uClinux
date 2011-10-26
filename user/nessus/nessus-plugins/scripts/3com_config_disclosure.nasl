#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# THIS SCRIPT WAS NOT TESTED !
# 
# Ref:
#
# Date: Mon, 24 Mar 2003 16:56:21 +0100 (CET)
# From: Piotr Chytla <pch@isec.pl>
# Reply-To: iSEC Security Research <security@isec.pl>
# To: bugtraq@securityfocus.com, <vulnwatch@vulnwatch.org>
#
# 
# Thanks to Piotr Chytla (pch@isec.pl) for sending me user_settings.cfg
# privately.
#

if(description)
{
 script_id(11480);
 script_bugtraq_id(7176);
 #script_cve_id("CVE-MAP-NOMATCH");
 # NOTE: no CVE id assigned (jfs, december 2003)
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "3com RAS 1500 configuration disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote 3com SuperStack II Remote Access System 1500 discloses
its user configuration (user_settings.cfg) when the file is
requested through the web interface.

This file contains the password (in clear text) of this device
as well as other sensitive information. 

An attacker may use this flaw to gain the control of this host

Solution : filter incoming traffic to this host
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Obtains the remote user_settings.cfg";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 script_require_ports(80, "Services/www");
 script_dependencies("http_version.nasl", "no404.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


req = http_get(item:"/user_settings.cfg", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);


if(raw_string(0x01, 0xB9, 0x00, 0x0B, 0x01, 0x03, 0x06, 0x01) >< res )
 	security_hole(port);
