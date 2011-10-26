#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(15436);
 script_bugtraq_id(11334);
 script_version("$Revision: 1.4 $");
 name["english"] = "php PHP_Variables Memory Disclosure";
 

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of PHP which is older than 5.0.2 or
4.39.

The remote version of this software is vulnerable to a memory disclosure
vulnerability in PHP_Variables. An attacker may exploit this flaw to
remotely read portions of the memory of the httpd process on the remote host.

See also : http://www.php.net/ChangeLog-5.php#5.0.2
Solution : Upgrade to PHP 5.0.2 or 4.3.9
Risk factor : High";



 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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
include("backport.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);
 
php = get_php_version(banner:banner);
if ( ! php ) exit(0);

if(ereg(pattern:"PHP/([0-3]\.*|4\.([0-2]\.|3\.[0-8][^0-9])|5\.0\.[01][^0-9])", string:php))
   security_hole(port);
