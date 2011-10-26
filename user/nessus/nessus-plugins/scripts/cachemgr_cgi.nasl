#
# This script was written by Alexis de Bernis <alexisb@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10034);
 script_bugtraq_id(2059);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0710");
 name["english"] = "RedHat 6.0 cachemgr.cgi";
 name["francais"] = "RedHat 6.0 cachemgr.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
 RedHat Linux 6.0 installs by default a squid cache manager cgi script with
no restricted access permissions. This script could be used to perform a
port scan from the cgi-host machine.

Solution :
If you are not using the box as a Squid www proxy/cache server then
uninstall the package by executing:
/etc/rc.d/init.d/squid stop ; rpm -e squid

If you want to continue using the Squid proxy server software, make the
following actions to tighten security access to the manager interface:
mkdir /home/httpd/protected-cgi-bin
mv /home/httpd/cgi-bin/cachemgr.cgi /home/httpd/protected-cgi-bin/

And add the following directives to /etc/httpd/conf/access.conf and
srm.conf:

--- start access.conf segment ---
# Protected cgi-bin directory for programs that
# should not have public access
order deny,allow
deny from all
allow from localhost
#allow from .your_domain.com
AllowOverride None
Options ExecCGI
--- end access.conf segment ---

--- start srm.conf segment ---
ScriptAlias /protected-cgi-bin/ /home/httpd/protected-cgi-bin/
--- end srm.conf segment ---

Risk factor : High";


 desc["francais"] = "Le script cachemgr.cgi est accessible, celui-ci permet
de scanner les ports d'une machine distante à partie de la machine 
hébergeant le script cgi.
 
Solution : 
Si vous n'utilisez pas Squid alors désinstallez le package en tapant
/etc/rc.d/init.d/squid stop ; rpm -e squid

Si vous utilisez Squid comme proxy, pour au moins sécuriser l'accès à ce script
tapez :
mkdir /home/httpd/protected-cgi-bin
mv /home/httpd/cgi-bin/cachemgr.cgi /home/httpd/protected-cgi-bin/

et ajoutez les directives suivantes à /etc/httpd/conf/access.conf et
srm.conf

--- start access.conf segment ---

# Protected cgi-bin directory for programs that
# should not have public access

<Directory /home/httpd/protected-cgi-bin>
order deny,allow
deny from all
allow from localhost
#allow from .your_domain.com
AllowOverride None
Options ExecCGI
</Directory>

--- end access.conf segment ---

--- start srm.conf segment ---
ScriptAlias /protected-cgi-bin/ /home/httpd/protected-cgi-bin/
--- end srm.conf segment ---


Facteur de risque : Sérieux"; 
 
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks whether the cachemgr.cgi is installed and accessible."; 
 summary["francais"] =  "Vérifie si le cgi cachemgr.cgi est installé et accessible.";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 A. de Bernis",
		francais:"Ce script est Copyright (C) 1999 A. de Bernis");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes",  "no404.nasl");
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

cgi = "cachemgr.cgi";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
