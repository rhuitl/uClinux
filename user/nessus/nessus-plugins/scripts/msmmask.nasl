# The script was written by Michel Arboi <arboi@alussinan.org>
# GNU Public Licence
#
# Affected: MondoSearch 4.4.5147 and below.
#           MondoSearch 4.4.5156 and above are NOT vulnerable.
#
# References:
#
# Message-ID: <20021010180935.14148.qmail@mail.securityfocus.com>
# From:"thefastkid" <thefastkid@ziplip.com>
# To:bugtraq@securityfocus.com
# Subject: MondoSearch show the source of all files
#

if(description)
{
 script_id(11163);
 script_version ("$Revision: 1.13 $");
  
 name["english"] = "msmmask.exe";
 script_name(english:name["english"]);
 
 desc["english"] = "
The msmmask.exe CGI is installed.
Some versions allow an attacker to read the source of any
file in your webserver's directories by using the 'mask'
parameter.

Solution : Upgrade your MondoSearch to version 4.4.5156 or later.

Risk factor : Low";


 desc["francais"] = "
Le CGI msmmask.exe est installé.
Certaines versions permettent à un pirate de 
lire n'importe quel fichier dans le même
répertoire via le paramètre 'mask'.

Solution : Mettez à jour votre logiciel 

Facteur de risque : Elevé";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/msmMask.exe";
 summary["francais"] = "Vérifie la présence de /cgi-bin/msmMask.exe";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi"
	);	

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 	

 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs())
{
p = string(dir, "/MsmMask.exe");
q = string(p, "?mask=/nessus", rand(), ".asp");
r = http_get(port: port, item: q);
c = http_keepalive_send_recv(port:port, data:r);
if (egrep(pattern: "Failed to read the maskfile .*nessus.*\.asp",
	string: c, icase: 1))
  {
    security_hole(port);
    exit(0);
  }

# Version at or below 4.4.5147
if (egrep(pattern: "MondoSearch for Web Sites (([0-3]\.)|(4\.[0-3]\.)|(4\.4\.[0-4])|(4\.4\.50)|(4\.4\.51[0-3])|(4\.4\.514[0-7]))", string: c))
  {
    security_hole(port);
    exit(0);
  }
}


