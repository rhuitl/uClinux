#
# This script was written by Renaud Deraison <deraison@nessus.org>
# 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10464);
 script_bugtraq_id(2242);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0368");
 
 name["english"] = "proftpd 1.2.0preN check";
 name["francais"] = "proftpd 1.2.0preN";
 
 script_name(english:name["english"],
             francais:name["francais"]);
             
 desc["english"] = "
The remote ProFTPd server is running a 1.2.0preN 
version.

All the 1.2.0preN versions contain several security
flaws that allow an attacker to execute arbitrary code
on this host.

Solution : Upgrade to a fixed FTP server - http://www.proftpd.net
Risk factor : High";
                 
                 
desc["francais"] = "
Le serveur ProFTPd distant fait tourner une version 1.2.0preN.

Toute la série des 1.2.0pre-quelquechose contient plusieurs
problèmes de sécurités permettant à un pirate d'executer
du code arbitraire sur ce système.

Solution : mettez proftpd à jour en version 1.2.0rc-quelquechose
          (http://www.proftpd.net)
Facteur de risque : Elevé";
                     
 script_description(english:desc["english"],
                    francais:desc["francais"]);
                    
 
 script_summary(english:"Checks if the version of the remote proftpd",
                francais:"Détermine la version du proftpd distant");
 script_category(ACT_ATTACK);
 script_family(english:"FTP", francais:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
                  
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#



include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);

if(egrep(pattern:"^220 ProFTPD 1\.2\.0pre.*", string:banner))security_hole(port);

