#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11735);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2003-0436", "CVE-2003-0437");
 script_bugtraq_id (7865, 7866); 
 
 name["english"] = "Mnogosearch overflows";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running the mnogosearch search.cgi CGI
program.

There is a flaw in older versions of this software which may allow
an attacker to gain a shell on this host.

Solution : Disable this CGI if you do not use it, or upgrade to the latest
version.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for search.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
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


foreach d (cgi_dirs()) {
 req = http_get(item:d + "/search.cgi" , port : port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( "mnoGoSearch" >< res ) {
 	security_hole(port);
	exit(0);
	}
}
