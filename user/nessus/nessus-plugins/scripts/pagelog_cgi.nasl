#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10591);
 script_bugtraq_id(1864);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0940");
 name["english"] = "pagelog.cgi";
 name["francais"] = "pagelog.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'pagelog.cgi' cgi is installed. This CGI has
a well known security flaw that lets an attacker create arbitrary
files on the remote server, ending in .txt, and reading arbitrary
files ending in .txt or .log

*** Warning : this flaw was not tested by Nessus. Check the existence
of /tmp/nessus_pagelog_cgi.txt on this host to find out if you
are vulnerable or not.

Solution : remove it from /cgi-bin.
Risk factor : High";


 desc["francais"] = "Le cgi 'pagelog.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de lire
des fichiers arbitraires sur le serveur finissant par .txt ou .log,
ou bien de créer des fichiers arbitraires en .txt

*** Warning : this flaw was not tested by Nessus. Check the existence
of /tmp/nessus_pagelog_cgi.txt on this host to find out if you
are vulnerable or not.

Solution : retirez-le de /cgi-bin.
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/pagelog.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/pagelog.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = 0;

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/pagelog.cgi"), port:port))
 {
  flag = 1;
  directory = dir;
  break;
 }
}

if(flag)
{
  req = http_get(item:string(directory,
  "/pagelog.cgi?name=../../../../../../tmp/nessus_pagelog_cgi"),
  		 port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  security_warning(port);
}
