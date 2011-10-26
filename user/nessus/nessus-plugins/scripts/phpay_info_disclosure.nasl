#
# This script was written by Renaud Deraison
#

if(description)
{
 script_version ("$Revision: 1.9 $");
 script_id(11531);
 script_bugtraq_id(7309, 7310, 7313);
 
 name["english"] = "PHPay Information Disclosure";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running PHPay, an online shop management system.

This package contains multiple information leakages which may allow
an attacker to obtain the physical path of the installation on the remote
host or even the exact version of the components used by the remote host,
by using the file admin/phpinfo.nasl which comes with it.

This files make a call to phpinfo() which display a lot of information
about the remote host and how PHP is configured.

An attacker may use this flaw to gain a more intimate knowledge
about the remote host and better prepare its attacks.

In addition to this, this version is vulnerable to a cross-site-scripting
issue which may let an attacker steal the cookies of your legitimate users.

Solution : Upgrade to PHPay 2.2.1 or newer
Risk factor : Low";


 script_description(english:desc["english"]);
 summary["english"] = "Checks for the presence of phpinfo.php";
 summary["francais"] = "Vérifie la présence de phpinfo.php";
 script_summary(english:summary["english"], francais:summary["francais"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
                francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl", "http_version.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);



foreach dir (make_list("/phpay", cgi_dirs()))
{
 req = http_get(item:string(dir, "/admin/phpinfo.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<title>phpinfo()</title>" >< res)
 	{
	security_warning(port);
	exit(0);
	}
}
