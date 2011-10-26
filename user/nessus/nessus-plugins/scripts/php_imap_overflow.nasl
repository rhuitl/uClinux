#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10628);
 script_bugtraq_id(6557);

 script_version ("$Revision: 1.13 $");
 name["english"] = "php IMAP overflow";
 name["francais"] = "php IMAP overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
A version of php which is older than 4.0.4
is running on this host.

There is a buffer overflow condition in the IMAP
module of this version which may allow an attacker
to execute arbitrary commands with the uid of the web
server, if this server is serving a webmail interface.

Solution : Upgrade to PHP 4.0.4

Reference : http://online.securityfocus.com/archive/1/166602

Risk factor : High";


 desc["francais"] = "
Une version de PHP plus ancienne que la version 4.0.4
tourne sur ce serveur.

Le module IMAP de cette version est vulnérable à un
dépassement de buffer permettant à un pirate d'executer
du code arbitraire sur ce système s'il offre une interface
de webmail.

Solution : Mettez PHP à jour en version 4.0.4
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
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
include("backport.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner)exit(0);
php = get_php_version(banner:banner);
if ( ! php ) exit(0);
 
if(ereg(pattern:"PHP/4\.0\.[0-3][^0-9]", string:php))
   security_hole(port);
