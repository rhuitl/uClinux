#
# This script was written by Gregory Duchemin <plugin@intranode.com> 
#
# See the Nessus Scripts License for details
#



#### REGISTER SECTION ####

if(description)
{

script_id(10715);
script_bugtraq_id(2527);
script_version("$Revision: 1.22 $");
#script_cve_id("");

#Name used in the client window.
name["english"]="BEA WebLogic Scripts Server scripts Source Disclosure";
name["francais"]="BEA WebLogic révèle les sources des scripts installés sur le serveur.";
script_name(english:name["english"], francais:name["francais"]);



#Description appearing in the Nessus client window when clicking on the name.

desc["english"]="
BEA WebLogic may be tricked into revealing the source code of JSP scripts
by using simple URL encoding of characters in the filename extension.

e.g.: default.js%70 (=default.jsp) won't be considered as a script but 
rather as a simple document.

Vulnerable systems: WebLogic version 5.1.0 SP 6

Immune systems: WebLogic version 5.1.0 SP 8

Solution: Use the official patch available at http://www.bea.com

Risk factor : Medium";
desc["francais"]="
Le serveur d'applications WEBLogic de la compagnie BEA comporte une faille de sécurite qui si elle 
est utilisée permet à un intrus d'accéder aux sources des scripts présents sur le serveur simplement
en encodant les caractères d'extension du fichier script au format ASCII.

exemple: default.js%70 ( = default.jsp ) ne sera pas interprete mais lu comme un simple fichier.

Versions vulnerables: WebLogic version 5.1.0 SP 6

Versions saines: WebLogic version 5.1.0 SP 8

Solution: Installer le patch disponible sur le site http://www.bea.com

Risque: intermediaire  ";
script_description(english:desc["english"], francais:desc["francais"]);


 
#Summary appearing in the tooltips, only one line.

summary["english"]="BEA WebLogic may be tricked into revealing the source code of JSP scripts.";
summary["francais"]="BEA WebLogic peut etre utilisé dans le but d'afficher les sources des scripts.";
script_summary(english:summary["english"], francais:summary["francais"]);



#Test among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);
script_copyright(english:"INTRANODE - 2001");

#Category in wich attack must be stored.

family["english"]="CGI abuses";
family["francais"]="Abus de CGI";
script_family(english:family["english"], francais:family["francais"]);
 


#from wich scripts this one is depending:
#Services Discovery +
#Default error page configured on Web sites not showing a usual 404
#thus to prevent any false positive answer.


script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl");
 
script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#### ATTACK CODE SECTION ####

function check(req, port)
{ 
request = http_get(item:req, port:port); 
response = http_keepalive_send_recv(port:port, data:request);
if( response == NULL ) exit(0);


#signature of Jsp.

signature = "<%=";

if (signature >< response) return(1);
 
return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "WebLogic" >!< sig ) exit(0);

foreach dir (cgi_dirs())
{
poison = string(dir, "/index.js%70");
if (check(req:poison, port:port)) security_warning(port:port); 
}

# Try with a known jsp file
files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(isnull(files))exit(0);
files = make_list(files);
file = ereg_replace(string:files[0], pattern:"(.*js)p$",
		    replace:"\1");
poison = string(file, "%70");
if(check(req:poison, port:port))security_warning(port);
 

