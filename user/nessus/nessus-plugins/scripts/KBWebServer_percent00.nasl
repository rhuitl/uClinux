#
# This script was written by Michel Arboi <arboi@alussinan.org> starting
# from roxen_percent.nasl
#
# GNU Public Licence
#
# References:
# From:"Securiteinfo.com" <webmaster@securiteinfo.com>
# To:nobody@securiteinfo.com
# Date: Sun, 7 Jul 2002 21:42:47 +0200 
# Message-Id: <02070721424701.01082@scrap>
# Subject: [VulnWatch] KF Web Server version 1.0.2 shows file and directory content
#

if(description)
{
 script_id(11166);
 script_version ("$Revision: 1.6 $");
 name["english"] = "KF Web Server /%00 bug";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Requesting a URL with '/%00' appended to it
makes some versions of KF Web Server to dump the listing of the  
directory, thus showing potentially sensitive files.

Risk factor : High
Solution : upgrade to the latest version of KF Web Server";

 desc["francais"] = "Demander une URL finissant par '/%00' 
force certaines versions de KF Web Server à afficher le 
contenu du répertoire, dévoilant ainsi des fichiers potentiellement 
sensibles.

Facteur de risque : Elevé.
Solution : Mettez KF Web Server à jour en sa dernière version";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Make a request like http://www.example.com/%00";
 summary["francais"] = "Envoie une requête du type http://www.example.com/%00";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

buffer = http_get(item:"/%00", port:port);
data   = http_keepalive_send_recv(port:port, data:buffer);
if ( data == NULL ) exit(0);


if (egrep(string: data, pattern: ".*File Name.*Size.*Date.*Type.*"))
{
 security_hole(port);
}
