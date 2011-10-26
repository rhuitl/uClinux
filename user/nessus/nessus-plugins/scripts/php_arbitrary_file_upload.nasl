#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(14770);
 script_bugtraq_id(11190);
 script_version("$Revision: 1.4 $");
 name["english"] = "php arbitrary file upload";
 

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of PHP which is
older than 4.3.9 or 5.0.2. 

The remote version of this software is affected by an unspecified file
upload vulnerability which may allow an attacker to upload arbitrary
files to the remote server.

See also : http://viewcvs.php.net/viewcvs.cgi/php-src/NEWS.diff?r1=1.1247.2.724&r2=1.1247.2.726
Solution : Upgrade to PHP 4.3.9 or 5.0.2 when available
Risk factor : Medium";



 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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
if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 php = get_php_version(banner:banner);
 if (! php) exit(0);
 if(ereg(pattern:"PHP/(4\.([0-2]\..*|3\.[0-8])|5\.0\.[01])[^0-9]", string:php))
   security_warning(port);
}
