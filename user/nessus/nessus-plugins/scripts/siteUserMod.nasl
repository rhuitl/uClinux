#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10253);
 script_bugtraq_id(951);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0117");
 
 name["english"] = "Cobalt siteUserMod cgi";
 name["francais"] = "Cobalt siteUserMod cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The Cobalt 'siteUserMod' CGI is installed. 
Older versions of this CGI allow any user to change the
administrator password.

Make sure you are running the latest version.

Solution : 

RaQ 1 Users, download :
ftp://ftp.cobaltnet.com/
	pub/experimental/security/siteUserMod/RaQ1-Security-3.6.pkg

RaQ 2 Users, download  :
ftp://ftp.cobaltnet.com/
	pub/experimental/security/siteUserMod/RaQ2-Security-2.94.pkg

RaQ 3 Users, download :
ftp://ftp.cobaltnet.com/
	pub/experimental/security/siteUserMod/RaQ3-Security-2.2.pkg


Risk factor : High";


 desc["francais"] = "
Le cgi 'siteUserMode' de Cobalt est installé. D'anciennes
versions de celui-ci permettent à n'importe quel utilisateur
de changer le mot de passe de l'administrateur. 
Vérifiez que vous utilisez la plus récente version de ce CGI.

Solution :
Si vous utilisez RaQ 1 :
ftp://ftp.cobaltnet.com/
	pub/experimental/security/siteUserMod/RaQ1-Security-3.6.pkg

Si vous utilisez RaQ 2 :
ftp://ftp.cobaltnet.com/
	pub/experimental/security/siteUserMod/RaQ2-Security-2.94.pkg

Si vous utilisez RaQ 3 :
ftp://ftp.cobaltnet.com/
	pub/experimental/security/siteUserMod/RaQ3-Security-2.2.pkg

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /.cobalt/siteUserMod/siteUserMod.cgi";
 summary["francais"] = "Vérifie la présence de /.cobalt/siteUserMod/siteUserMod.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
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

cgi = string("/.cobalt/siteUserMod/siteUserMod.cgi");
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);

