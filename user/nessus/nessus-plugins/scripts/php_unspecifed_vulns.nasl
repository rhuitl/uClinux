#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(18033);
 script_bugtraq_id(13143, 13163, 13164);
 script_version("$Revision: 1.6 $");
 name["english"] = "PHP Multiple Unspecified Vulnerabilities";
 

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of PHP which is older than 5.0.3 or
4.3.11

The remote version of this software is vulnerable to a set of 
vulnerabilities in the EXIF module which have been fixed by the PHP Group.

See also : http://www.php.net/ChangeLog-5.php#5.0.4
           http://www.php.net/ChangeLog-4.php#4.3.11

Solution : Upgrade to PHP 5.0.3 or 4.3.11
Risk factor : Medium";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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
if ( ! port ) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);

php = get_php_version(banner:banner);
if ( ! php ) exit(0);
 
if(egrep(pattern:"PHP/([0-3]\.*|4\.([0-2]\.|3\.([0-9][^0-9]|10[^0-9]))|5\.0\.[0-3][^0-9])", string:php))
   security_warning(port);
