#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(16012);
 script_bugtraq_id(12044);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "ArGoSoft Mail Server multiple flaws(2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the ArGoSoft WebMail interface.

There are multiple flaws in this interface which may allow an attacker
to bypass authentication, inject HTML in the e-mails read by the users
and even to read arbitrary files on that server.

*** Nessus solely relied on the banner of this service to issue
*** this alert.

Solution : Upgrade to ArGoSoft 1.8.7.0 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the version of the remote ArGoSoft server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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
  if(ereg(pattern:".*Version.*\((0\.|1\.([0-7]\.|8\.([0-6]\.])))\)", string:vers))security_warning(port);
 }
}
