#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# Ref:
#
# Date: Tue, 25 Mar 2003 14:31:59 +0000
# From: Sir Mordred <mordred@s-mail.com>
# To: bugtraq@securityfocus.com
# Subject: @(#)Mordred Labs advisory - Integer overflow in PHP socket_iovec_alloc() function


if(description)
{
 script_id(11468);
 script_bugtraq_id(7187, 7197, 7198, 7199, 7210, 7256, 7259);
 script_cve_id("CVE-2003-0166");

 script_version("$Revision: 1.14 $");
 name["english"] = "php socket_iovec_alloc() integer overflow";
 

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of PHP which is
older than 4.3.2

There is a flaw in this version which may allow an attacker who has the 
ability to inject an arbitrary argument to the function socket_iovec_alloc() 
to crash the remote service and possibly to execute arbitrary code.

For this attack to work, PHP has to be compiled with the option
--enable-sockets (which is disabled by default), and an attacker needs to 
be able to pass arbitrary values to socket_iovec_alloc().

Other functions are vulnerable to such flaws : openlog(), socket_recv(), 
socket_recvfrom() and emalloc()

Solution : Upgrade to PHP 4.3.2
Risk factor : Low";




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
if ( ! port ) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);
php = get_php_version(banner:banner);
if ( ! php ) exit(0);

if(ereg(pattern:"PHP/([1-3]\..*|4\.([0-2]\..*|3\.[0-1]))[^0-9]", string:php))
   security_warning(port);
