#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16364);
 script_bugtraq_id(12502);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "ArGoSoft Mail Server Directory Traversal Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the ArGoSoft WebMail interface.

There are multiple flaws in this interface which may allow an attacker
to read arbitrary files on the remote server by exploiting a directory
traversal vulnerability in the remote software.

Solution : Upgrade to ArGoSoft 1.8.7.4 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the version of the remote ArGoSoft server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(get_port_state(port))
{
 res = http_get_cache(item:"/", port:port);
 if( res == NULL ) exit(0);
 if((vers = egrep(pattern:".*ArGoSoft Mail Server.*Version", string:res)))
 {
  if(ereg(pattern:".*Version.*\((0\.|1\.([0-7]\.|8\.([0-6]\.|7\.[0-3])))\)", 
  	  string:vers))security_hole(port);
 }
}
