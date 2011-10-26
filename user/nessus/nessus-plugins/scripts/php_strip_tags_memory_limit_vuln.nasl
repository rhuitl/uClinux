#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# ref: Stefan Esser 
# This script is released under the GNU GPLv2

if(description)
{
 script_id(13650);
 script_bugtraq_id(10724, 10725);
 script_cve_id("CVE-2004-0594","CVE-2004-0595");
 script_version("$Revision: 1.9 $");
 name["english"] = "php < 4.3.8";
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7870");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7871");

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of PHP 4.3 which is older or equal to 
4.3.7.

PHP is a scripting language which acts as a module for Apache or as a standalone
interpreter. There is a bug in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host if the option
memory_limit is set. Another bug in the function strip_tags() may allow
an attacker to bypass content-restrictions when submitting data and may
lead to cross-site-scripting issues.

Solution : Upgrade to PHP 4.3.8 
Risk factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 if ( !defined_func("bn_random") )
 	script_dependencie("http_version.nasl");
 else
	script_dependencie("http_version.nasl", "redhat-RHSA-2004-392.nasl", "redhat-RHSA-2004-395.nasl");

 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("backport.inc");

if ( get_kb_item("CVE-2004-0594") || get_kb_item("CVE-2004-0595") ) exit(0);

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner)exit(0);
php = get_php_version(banner:banner);
if (! php ) exit(0);

if(ereg(pattern:"PHP/4\.3\.[0-7][^0-9]", string:php))
   security_hole(port);
