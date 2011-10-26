#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10957);
 script_version ("$Revision: 1.13 $");
 name["english"] = "JServ Cross Site Scripting";
 name["francais"] = "JServ Cross Site Scripting";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server is vulnerable to a cross-site scripting issue.

Description :

Older versions of JServ (including the version shipped with Oracle9i App 
Server v1.0.2) are vulnerable to a cross site scripting attack using a 
request for a non-existent .JSP file.

Solution : 

Upgrade to the latest version of JServ available at http://java.apache.org. 
Also consider switching from JServ to TomCat, since JServ is no longer 
maintained.

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for JServ Cross Site Scripting";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "Web Servers";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss")))exit(0);


banner = get_http_banner(port:port);
if ( ! banner || "JServ" >!< banner ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/a.jsp/<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if("<SCRIPT>alert(document.domain)</SCRIPT>" >< res) security_warning(port);
}
