#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11807);
 script_bugtraq_id(8201);

 script_version("$Revision: 1.7 $");
 name["english"] = "php < 4.3.3";

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of PHP 4.3 which is older or equal to 
4.3.2.

There is a flaw in this version which may allow a local attacker to 
bypass the safe mode and gain unauthorized access to files on the local
system, thanks to a flaw in the function php_safe_mode_include_dir().

Solution : Upgrade to PHP 4.3.3 when it is available
Risk factor : Medium";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
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
if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 php = get_php_version(banner:banner);
 if ( ! php ) exit(0);
 if(ereg(pattern:"PHP/4\.3\.[0-2][^0-9]", string:php))
   security_warning(port);
}
