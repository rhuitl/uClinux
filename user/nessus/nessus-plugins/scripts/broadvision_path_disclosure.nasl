#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10686);
 script_bugtraq_id(2088);
 script_cve_id("CVE-2001-0031");
 script_version ("$Revision: 1.14 $");
 name["english"] = "BroadVision Physical Path Disclosure Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
BroadVision will reveal the physical path of the 
webroot when asked for a non-existent .jsp file
if it is incorrectly configured. Whilst printing errors 
to the output is useful for debugging applications, this 
feature should not be enabled on production servers.

Solution : There was no solution ready when this vulnerability was written;
Please contact the vendor for updates that address this vulnerability.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for BroadVision Physical Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Actual check starts here...
# Check makes a request for non-existent php3 file...

include("http_func.inc");

port = get_http_port(default:80);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:string("/nosuchfile-", rand(), "-", rand(), ".jsp"), 
 		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if(egrep(string:r, pattern:".*Script /.*/nosuchfile-.*"))
 	security_warning(port);

 }
}
