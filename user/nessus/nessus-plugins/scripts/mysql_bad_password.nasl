#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 
 script_id(10343);  
 script_bugtraq_id(975);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0148");
 name["english"] = "MySQLs accepts any password";
 name["francais"] = "MySQLs accepte n'importe quel mot de passe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of MySQL which is 
older than (or as old as) version 3.22.30 or 3.23.10

If you have not patched this version, then
any attacker who knows a valid username can
access your tables without having to enter any
valid password.

Risk factor : High
Solution : Upgrade to a newer version, or
edit the file mysql-xxx/sql/password.c, and
search for the 'while(*scrambled)' loop. In front
of it, add : 'if(strlen(scrambled) != strlen(to))return 1'";

	
 desc["francais"] = "
Vous faites tourner une version de MySQL
plus ancienne ou égale à la version 3.22.30 ou 3.23.10

Cette version est vulnérable à un problème de
vérification de mot de passe qui permet à
n'importe quel pirate connaissant un nom d'utilisateur
valide d'accéder à vos tables.


Facteur de risque : Elevé
Solution : Mettez votre version à jour,
ou bien patchez le fichier  mysql-xxx/sql/password.c :
	- cherchez la boucle 'while(*scrambled)'
	- ajoutez devant :
		if(strlen(scrambled)!=strlen(to))return 1
";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the remote MySQL version";
 summary["francais"] = "Vérifie la version de MySQL";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port)port = 3306;

ver = get_mysql_version(port:port);
if (ver == NULL) exit(0);
if(ereg(pattern:"^3\.(22\.(2[6789]|30)|23\.([89]|10))", string:ver))security_hole(port);

