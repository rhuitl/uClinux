#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10535);
 script_bugtraq_id(1786);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2000-0967");
 name["english"] = "php log";
 name["francais"] = "log php";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
A version of php which is older than 3.0.17
or than 4.0.3 is running on this host.


If the option 'log_errors' is set to 'On' in php.ini,
then an attacker may execute arbitrary code on this host.


Solution : make sure that 'log_errors' is set to 'Off' in your php.ini,
           or install the latest version of PHP :
	   http://www.php.net/do_download.php?download_file=php-4.0.3.tar.gz
	   or
	   http://www.php.net/distributions/php-3.0.17.tar.gz

Risk factor : High";


 desc["francais"] = "
Une version de php plus vieille que la 3.0.17 ou que la 4.0.3
tourne sur ce serveur.

Si l'option 'log_errors' est mise à 'On' dans php.ini, 
alors un pirate est en mesure de faire executer du coder
arbitraire à ce serveur.

Solution : assurez-vous que l'option 'log_errors' est mise à 'Off' dans
           votre php.ini, ou bien installez les dernières versions
	   de PHP :
	   http://www.php.net/do_download.php?download_file=php-4.0.3.tar.gz
	   or
	   http://www.php.net/distributions/php-3.0.17.tar.gz
	   
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);

 serv = egrep(string:banner, pattern:"^Server:.*$");
 if(ereg(pattern:"(.*PHP/3\.0\.((1[0-6])|([0-9]([^0-9]|$))))|(.*PHP/4\.0\.[0-2]([^0-9]|$))",
          string:serv))
 {
   security_hole(port);
 }
}
 
