#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12088);
 script_cve_id("CVE-2004-0348");
 script_bugtraq_id(9799);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SpiderSales Shopping Cart SQL injection";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running the SpiderSales Shopping Cart CGI suite.

There is a bug in this suite which may allow an attacker
to force it to execute arbitrary SQL statements on the remote
host. An attacker may use this flaw to gain the control of the remote
website and possibly execute arbitrary commands on the remote host.

Solution: Disable this suite or upgrade to the latest version
Risk factor: High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for the presence of SpiderSales Shopping cart";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl", "no404.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs())
{
 req = http_get(item: dir + "/viewCart.asp?userID='", port: port );
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"userID=''' and storeID=", string:res) ) 
   {
	security_hole ( port );
	exit ( 0 );
   }
}

