

#
# This script was written by Julio César Hernández <jcesar@inf.uc3m.es>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive

if(description)
{
 script_id(10316);
#  script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "WinSATAN";
 name["francais"] = "WinSATAN";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "WinSATAN is installed. 

This backdoor allows anyone to partially take control
of the remote system.

An attacker may use it to steal your password or prevent
your system from working properly.

Solution : use RegEdit, and find 'RegisterServiceBackUp'
in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
The value's data is the path of the file.
If you are infected by WinSATAN, then
the registry value is named 'fs-backup.exe'.

Additional Info : http://online.securityfocus.com/archive/75/17508
Additional Info : http://online.securityfocus.com/archive/75/17663

Risk factor : High";


 desc["francais"] = "WinSATAN est installé.

Cette backdoor permet à n'importe qui
de prendre partiellement le controle
de la machine distante.

Un pirate peut l'utiliser pour voler
vos mots de passes ou vous empecher
de travailler convenablement.

Solution : avec RegEdit, trouvez 'RegisterServiceBackup'
dans HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
Les données de cette valeur representent le nom du
fichier en question.
Si vous etes infecté par WinSATAN, alors
le nom de la valeur est 'fs-backup.exe'.

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of WinSATAN";
 summary["francais"] = "Determines la presence de WinSATAN";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Julio César Hernández",
		francais:"Ce script est Copyright (C) 2000 Julio César Hernández");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(999);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
if(get_port_state(999))
{
soc = open_sock_tcp(999);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:"uyhw6377w", pass:"bhw32qw"))security_hole(999);
 close(soc);
}
}
