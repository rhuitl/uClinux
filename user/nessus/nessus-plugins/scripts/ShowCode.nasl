#
# ShowCode ASP
#
# This plugin was written in C by Immo Goltz <Immo.Goltz@gecits-eu.com>
# and is released under the GPL
#
# - Description taken from  http://www.l0pht.com/advisories.html
#
# Converted in NASL by Renaud Deraison <deraison@cvs.nessus.org>


if(description)
{
 script_id(10007);
 script_bugtraq_id(167);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0736");
 name["english"] = "ShowCode possible";
 name["francais"] = "ShowCode possible";
 name["deutsch"] = "ShowCode moeglich";
  
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 
 desc["english"] = "
Internet Information Server (IIS) 4.0 ships with a set of sample files to
help web developers learn about Active Server Pages (ASP). One of these
sample files, 'showcode.asp' (installed in /msadc/Samples/SELECTOR/), is
designed to view the source code of the sample applications via a web

browser.
The 'showcode.asp' file does inadequate security checking and allows anyone
with a web browser to view the contents of any text file on the web server.
This includes files that are outside of the document root of the web server.

The 'showcode.asp' file is installed by default at the URL:
http://www.YOURSERVER.com/msadc/Samples/SELECTOR/showcode.asp
It takes 1 argument in the URL, which is the file to view.
The format of this argument is: source=/path/filename

This is a fairly dangerous sample file since it can view the contents of any 
other files on the system. The author of the ASP file added a security check to 
only allow viewing of the sample files which were in the '/msadc' directory on 
the system. The problem is the security check does not test for the '..'
characters within the URL. The only checking done is if the URL contains the
string '/msadc/'. This allows URLs to be created that view, not only files
outside of the samples directory, but files anywhere on the entire file
system that the web server's document root is on.

The full description can be found at: http://www.l0pht.com/advisories.html

Solution : For production servers, sample files should never be installed, so
delete the entire /msadc/samples directory. If you must have the
'showcode.asp' capability on a development server, the 'showcode.asp' file 
should be modified to test for URLs with '..' in them and deny those requests.

Risk factor : High";


 desc["francais"] = "
Le fichier showcode.asp est installé dans
 /msadc/Samples/SELECTOR
 
Internet Information Server (IIS) 4.0
est livré avec un ensemble de fichiers
d'exemple faits pour faire connaitre
les Active Servers Page (ASP) aux 
dévelopeurs web. Un des ces fichiers
d'exemple, 'showcode.asp', est fait
pour voir le code source des programmes
d'exemple au travers d'un browser web.
Le fichier 'showcode.asp' fait des vérifications
sécuritaires inadéquates et permet à quiconque
possèdant un browser web de lire des fichiers 
arbitraires sur la machine distante, ce qui
inclut des fichiers qui sont en dehors 
de la racine du serveur web.

Le fichier showcode.asp est installé par 
défaut à :
http://www.someserver.com/msadc/Samples/SELECTOR/showcode.asp

Il prend un argument dans l'URL, qui est le nom du fichier
à lire.
Le format de cet argument est :
source=/chemin/fichier


Ce fichier d'exemple est dangereux. Il peut lire
le contenu de n'importe quel fichier sur le système.
Son auteur a ajouté une vérification sécuritaire
qui ne permet la lecture que des fichiers présents
dans le dossier '/msadc'. Le problème étant que
ce test de sécurité ne teste pas les caractères
'..'. La seule vérification qui est faite est
que la chaine '/msadc' est contenue dans 
l'URL. Cela permet la création d'URLs qui peuvent
lire des fichiers arbitraires sur la machine distante.

La description complete de ce problème peut être
lue à :
http://www.l0pht.com/advisories.html

Solution : les serveurs de productions ne doivent
pas garder les documents d'exemple, donc effacez
le répertoire /msadc/samples. Si vous avez besoin
de showcode.asp, alors modifiez-le de telle sorte
qu'il detecte des URLs ayant '..' et qu'il refuse
ces requêtes.

Facteur de risque : Elevé";

 desc["deutsch"] = "
Die Datei showcode.asp ist installiert unter
 /msadc/Samples/SELECTOR/

Internet Information Server (IIS) 4.0 wird mit einigen
Beispielseiten geliefert, die Web-Entwicklern das erlernen
der Active Server Pages (ASP) erleichtern sollen. Eine
dieser Beispieldateien, 'showcode.asp', ist gedacht, um 
den Programmcode der Beispielprogramme in einem Browser
anzuzeigen.
Die Datei 'showcode.asp' nutzt nur inadequate Sicherheitschecks
und erlaubt jedermann das Lesen von jeglichen Textdateien
auf dem Webserver. Dies beinhaltet auch Dateien, die sich
ausserhalb des Webserver-Verzeichnisbaumes befinden!

showcode.asp findet sich Standardmaessig unter der URL:
http://www.someserver.com/msadc/Samples/SELECTOR/showcode.asp

Es akzeptiert ein Argument in der URL, und zwar den Dateinamen
der Datei, die angezeigt werden soll. Das Format dieses 
Argumentes ist source=/Pfad/Dateiname

Dies ist eine ziemlich gefaehrliche Beispieldatei. Sie kann 
den Inhalt von Dateien auf dem Serversystem anzeigen. Der
Autor der ASP-Datei hat einen Sicherheitscheck hinzugefuegt, 
so dass nur Dateien angezeigt werden koennen, die sich im
'/msadc' Beispielpfad befinden. Leider ueberprueft dieser
Sicherheitscheck nicht, ob sich die Zeichen '..' im Dateinamen
befinden. Es wird lediglich ueberprueft, ob sich die Zeichenkette
'/msadc' in der URL befindet. Somit koennen nicht nur Dateien 
innerhalb des msadc-Pfades, sondern auch solche ausserhalb des
Server-Wurzelverzeichnisses angezeigt werden. 
Man kann auf jede Datei auf der Festplatte zugreifen, auf der
sich der Webserver befindet.

Eine genaue Beschreibung findet man unter
http://www.l0pht.com/advisories.html

Loesung: Auf Servern im produktiven Einsatz sollte man niemals
Beispieldateien installiert lassen. Loeschen Sie daher das komplette
/msadc/samples Verzeichnis. Wenn Sie die Faehigkeiten des showcode.asp
auf Ihrem Server benoetigen, so sollten Sie es dahingehend 
modifizieren, dass es URLs mit '..' verbietet.

Risiko Faktor:	Ernst";
 

 script_description(english:desc["english"], francais:desc["francais"], deutsch:desc["deutsch"]);
 
 summary["english"] = "Determines the presence of showcode.asp";
 summary["francais"] = "Détermine la présence de showcode.asp";
 summary["deutsch"] = "Ueberprueft auf Existenz von showcode.asp";

 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Immo Goltz <Immo.Goltz@gecits-eu.com>",
		francais:"Ce script est Copyright (C) 1999 Immo Goltz <Immo.Goltz@gecits-eu.com>",
		deutsch:"Dieses Script ist Copyright (C) 1999 Immo Goltz <Immo.Goltz@gecits-eu.com>");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 family["deutsch"] = "CGI Sicherheitsluecken";
 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


cgi = string("/msadc/Samples/SELECTOR/showcode.asp");
if ( is_cgi_installed_ka(item:cgi, port:port) )
 {
  item = "/msadc/Samples/SELECTOR/showcode.asp?source=/msadc/Samples/../../../../../winnt/win.ini";
  req = http_get(item:item, port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   r = tolower(r);
   if("[fonts]"  >< r){
	security_hole(port);
	}
   exit(0);
  }
  security_warning(port);
 }

  

