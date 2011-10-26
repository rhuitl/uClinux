#
# This script was written by Gregory Duchemin <plugin@intranode.com>
#
# See the Nessus Scripts License for details
#
#
# Title: WebDab Extensions Memory Leakage in IIS5/Win2K using LOCK Method.
#
#
#

#### REGISTER SECTION ####

if(description)
{
 script_id(10732);
 script_bugtraq_id(2736);

 script_version ("$Revision: 1.20 $");


#Name used in the client window.

name["english"] = "IIS 5.0 WebDav Memory Leakage";
name["francais"] = "IIS 5.0 WebDav, fuites de memoire.";
script_name(english:name["english"], francais:name["francais"]);


#Description appearing in the Nessus client window when clicking on the name.

desc["english"]="
The WebDav extensions (httpext.dll) for Internet Information
Server 5.0 contains a flaw that may allow a malicious user to
consume all available memory on the target server by sending 
many requests using the LOCK method associated to a non 
existing filename.
 
This concern not only IIS but the entire system since the flaw can 
potentially exhausts all system memory available.

Vulnerable systems: IIS 5.0 ( httpext.dll versions prior to 0.9.3940.21 )

Immune systems: IIS 5 SP2( httpext.dll version 0.9.3940.21)

Solution: Download Service Pack 2/hotfixes from Microsoft web
at http://windowsupdate.microsoft.com

Risk factor : High";



desc["francais"]="
Les extensions WebDav de IIS 5.0 comporte des fuites de mémoire qui 
permettent à un utilisateur malicieux de consommer toute la mémoire 
disponible en utilisant la methode LOCK de façon répetée vers un fichier
 non existant, provoquant ainsi un denie de service du serveur puisque 
 la totalité de la mémoire peut ainsi etre perdue.

Versions vulnérables: IIS 5.0 ( httpext.dll avant la 0.9.3940.21 )

Version saine: IIS 5 hotfix/SP2 ( httpext.dll version 0.9.3940.21 )

Solution: Installer le service pack 2 ou les hotfix disponibles a 
http://www.microsoft.com/windows2000/downloads/servicepacks/sp2/default.asp.

Facteur de risque : élevé ";



script_description(english:desc["english"], francais:desc["francais"]);




#Summary appearing in the tooltips, only one line. 

summary["english"]="Check the presence of a Memory Leakage in the IIS 5 httpext.dll (WebDav).";
summary["francais"]="Vérifie la présence de fuite de mémoire dans le module WebDav de IIS5.";	
script_summary(english:summary["english"], francais:summary["francais"]);


#Test it among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);

#Copyright stuff

script_copyright(english:"INTRANODE - 2001");

family["english"]="Denial of Service";
family["francais"]="Déni de service";
script_family(english:family["english"], francais:family["francais"]);



#Portscan the target/try SMB SP test  before executing this script.

script_dependencies("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");

#optimization, stop here if either no web service was found 
# by find_service.nes plugin or no port 80 was open.

script_require_ports(80, "Services/www");

exit(0);
}



#### ATTACK CODE SECTION ####

include("http_func.inc");



function check(poison, port)
{ 
 soc = http_open_socket(port);
 if(!soc) exit(0); 

 send(socket:soc, data:poison);
 code = recv_line(socket:soc, length:1024);
 http_close_socket(soc); 

 signature = "HTTP/1.1 207";


 if((signature >< code)) 
	return(1);
    else 
	return(0);
}

port = get_http_port(default:80);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig )
	{
	if ( "IIS" >!< sig ) exit(0);
	}
else	{
	sig = get_http_banner(port:port);
	if ( !egrep(pattern:"^Server:.*IIS", string:sig )) exit(0);
	}

if(!get_port_state(port)) exit(0);



quote = raw_string(0x22);
poison = string("PROPFIND / HTTP/1.1\r\n",
    	     "Host: ", get_host_name(), "\r\n",
	     "Content-Type: text/xml\r\n",
	     "Content-Length: 110\r\n\r\n",
	     "<?xml version=", quote, "1.0", quote, "?>\r\n",
	     "<a:propfind xmlns:a=", quote, "DAV:", quote, ">\r\n",
	     " <a:prop>\r\n",
	     "  <a:displayname:/>\r\n",
	     " </a:prop>\r\n",
	     "</a:propfind>\r\n");


#Verify the presence of IIS 5.0, DAV module and a valid return server code.

if (!(check(poison:poison, port:port))) exit(0);

#Try to get a Service pack via the registry.
SP = get_kb_item("SMB/Win2K/ServicePack");

if (!SP)
{
report="IIS 5 is online but service Pack could not be determined.
Please check that SP2 is correctly installed to prevent the WebDav 
Memory Leakage DOS vulnerability.

Solution : SP2 and hotfix are available at 
http://www.microsoft.com/windows2000/downloads/servicepacks/sp2/default.asp.

Risk factor : High";

security_warning(port:port, data:report);
}
else
{ 
if (("Service Pack 1" >< SP) || ("Beta2" >< System) || ("Beta3" >< System) || ("RC1" >< System) || ("Build 2128" >< System))
 {
report="
IIS 5 is online but the Service Pack 2 doesn't seem to be installed.
The WebDav Memory Leakage DOS vulnerability can potentially put the 
server to its knees.
Solution : SP2 and hotfix are available at 
http://www.microsoft.com/windows2000/downloads/servicepacks/sp2/default.asp.

Risk factor : High";
security_hole(port:port, data:report);
 }
}

