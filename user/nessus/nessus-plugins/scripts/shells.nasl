#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10252);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0509");
 
 name["english"] = "Shells in /cgi-bin";
 name["francais"] = "Shells dans /cgi-bin";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server has one of these shells installed
in /cgi-bin :
	ash, bash, csh, ksh, sh, tcsh, zsh

Leaving executable shells in the cgi-bin directory of
a web server may allow an attacker to execute arbitrary
commands on the target machine with the privileges of the 
http daemon (usually root or nobody).

Solution : Remove all the shells from /cgi-bin.

Risk factor : High";

 desc["francais"] = "
Le serveur web distant à l'un des shells suivants installé
dans /cgi-bin :
	ash, bash, csh, ksh, sh, tcsh, zsh
	
Laisser un shell executable dans le repertoire cgi-bin 
peut permettre à des utilisateurs distants d'executer
des commandes arbitraires sur la machine avec l'UID
du serveur web, ce qui est une menace en matière de
sécurité.

Solution : enlevez tous les shells de /cgi-bin

Facteur de risque : sérieux";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of various shells in /cgi-bin";
 summary["francais"] = "Vérifie la présence de plusieurs shells dans /cgi-bin";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
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

sh = make_list("ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh");
 
foreach dir (cgi_dirs())
{
 foreach s (sh)
 {
  ok = is_cgi_installed_ka(item:string(dir, "/", s), port:port);
  if(ok)
  {
   security_hole(port);
   exit(0);
  }
 }
}
