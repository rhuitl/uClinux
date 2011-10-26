#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10122);
 script_bugtraq_id(739);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-1999-0951");
 name["english"] = "imagemap.exe";
 name["francais"] = "imagemap.exe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'imagemap.exe' cgi is installed. This CGI 
is vulnerable to a buffer overflow that will allow a remote user
to execute arbitrary commands with the privileges of your httpd
server (either nobody or root).

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'imagemap.exe' est installé. Un
dépassement de buffer permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec 
les privilèges de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflows /cgi-bin/imagemap.exe";
 summary["francais"] = "Overflow de /cgi-bin/imagemap.exe";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);

flag = 0;

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/imagemap.exe"), port:port))
 { 
  flag = 1;
  directory = dir;
  break;
 }
}

if(!flag)exit(0);

s = string(directory, "/imagemap.exe?", crap(5000));
soc = http_open_socket(port);
if(soc)
 {
 s = http_get(item:s, port:port);
 send(socket:soc, data:s);
 r = http_recv(socket:soc);
 if(!r)security_hole(port);
 http_close_socket(soc);
 }


