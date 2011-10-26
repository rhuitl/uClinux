#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10053);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-0660");

 name["english"] = "DeepThroat";
 name["francais"] = "DeepThroat";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "DeepThroat is installed. 

This backdoor allows anyone to
partially take the control of 
the remote system.

An attacker may use it to steal your
password or prevent you from working
properly.

Solution : use regedit or regedt32, and find 'SystemDLL32'
in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
The value's data is the path of the file.
If you are infected by DeepThroat 2 or 3, then
the registry value is named 'SystemTray'.

After cleaning the infected machine, you should manually
find the root cause of the initial infection.  Alternatively,
you may wish to completely rebuild the system, as the backdoor
may have been used to create other backdoors into the system.

Risk factor : High";


 desc["francais"] = "DeepThroat est installé.

Cette backdoor permet à n'importe qui
de prendre partiellement le controle
de la machine distante.

Un pirate peut l'utiliser pour voler
vos mots de passes ou vous empecher
de travailler convenablement.

Solution : avec RedEdit, trouvez 'SystemDLL32'
dans HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
Les données de cette valeur representent le nom du
fichier en question.
Si vous etes infecté par DeepThroat 2 ou 3, alors
le nom de la valeur est 'SystemTray'.

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of DeepThroat";
 summary["francais"] = "Determines la presence de DeepThroat";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_keys("Settings/ThoroughTests");
 
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

port = 2140;
if(get_udp_port_state(port))
{
 data = raw_string(0x00,0x00);
 soc = open_sock_udp(port);
 if(soc)
 {
 send(socket:soc, data:data, length:2);
 result = recv(socket:soc, length:4096);
 if("My Mouth is Open" >< result)security_hole(port);
 close(soc);
 }
}
