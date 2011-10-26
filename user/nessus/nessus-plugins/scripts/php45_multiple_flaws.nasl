#
# (C) Tenable Network Security
#
# Ref:
#  Date: Wed, 15 Dec 2004 19:46:20 +0100
#  From: Stefan Esser <sesser@php.net>
#  To: bugtraq@securityfocus.com, full-disclosure@lists.netsys.com
#  Subject: Advisory 01/2004: Multiple vulnerabilities in PHP 4/5  
#

if(description)
{
 script_id(15973);
 script_bugtraq_id(11964, 11981, 11992, 12045);
 script_version("$Revision: 1.7 $");
 name["english"] = "php4/5 Vulnerabilities";
 

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of PHP which is older than 5.0.3 or
4.3.10.

The remote version of this software is vulnerable to various security
issues which may, under certain circumstances, to execute arbitrary code
on the remote host, provided that we can pass arbitrary data to some
functions, or to bypass safe_mode.

See also : http://www.php.net/ChangeLog-5.php#5.0.3
Solution : Upgrade to PHP 5.0.3 or  4.3.10
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of PHP";
 summary["francais"] = "Vérifie la version de PHP";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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

 if(ereg(pattern:"PHP/(4\.([012]\.|3\.[0-9][^0-9])|5\.0\.[012][^0-9])", string:php))
   security_hole(port);
}
