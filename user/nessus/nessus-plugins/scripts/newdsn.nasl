#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10360);
 script_bugtraq_id(1818);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0191");

 name["english"] = "newdsn.exe check";
 name["francais"] = "verification de newdsn.exe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The CGI /scripts/tools/newdsn.exe is present.

This CGI allows any attacker to create files
anywhere on your system if your NTFS permissions
are not tight enough, and can be used to overwrite
DSNs of existing databases.

Solution : Remove newdsn.exe
Risk factor : High";


 desc["francais"] = "
Le CGI /scripts/tools/newdsn.exe est présent.

Ce CGI permet à n'importe qui de créer des fichiers
a des endroits arbitraires sur votre système
(pourvu que vos permissions NTFS soient laxistes)
ainsi que d'écraser des DSNs sur des bases qui
existent.

Solution : retirez-le
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /scripts/tools/newdsn.exe";
 summary["francais"] = "Vérifie la présence de /scripts/tools/newdsn.exe";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
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

cgi = "/scripts/tools/newdsn.exe";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
