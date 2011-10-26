#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10850);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0006");
 script_bugtraq_id(4034);
 script_cve_id("CVE-2002-0562");
 script_version("$Revision: 1.13 $");
 name["english"] = "Oracle 9iAS Globals.jsa access";
 name["francais"] = "Oracle 9iAS Globals.jsa access";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
In the default configuration of Oracle9iAS, it is possible to make 
requests for the globals.jsa file for a given web application. 
These files should not be returned by the server as they often 
contain sensitive information.


Solution: 
Edit httpd.conf to disallow access to *.jsa.

References:
http://www.nextgenss.com/advisories/orajsa.txt
http://www.oracle.com

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Oracle9iAS Globals.jsa access";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
# Make a request for one of the demo files .jsa files. This can be 
# improved to use the output of webmirror.nasl, allowing the plugin to
# test for this problem in configurations where the demo files have
# been removed.

 req = http_get(item:"/demo/ojspext/events/globals.jsa",
 		port:port); 
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("event:application_OnStart" >< r)	
 	security_warning(port);

 }
}
