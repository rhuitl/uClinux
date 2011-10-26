#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10570);
 script_bugtraq_id(1876);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-1024");
 name["english"] = "Unify eWave ServletExec 3.0C file upload";
 name["francais"] = "Unify eWave ServletExec 3.0C file upload";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
ServletExec has a servlet called 'UploadServlet' in its server
side classes. UploadServlet, when invokable, allows an
attacker to upload any file to any directory on the server. The
uploaded file may have code that can later be executed on the
server, leading to remote command execution.

Solution : Remove it
Risk factor : High";


 


 script_description(english:desc["english"]);
 
 summary["english"] = "Unify eWave ServletExec 3.0C file upload";
 summary["francais"] = "Unify eWave ServletExec 3.0C file upload";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Matt Moore",
		francais:"Ce script est Copyright (C) 2000 Matt Moore");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"/servlet/nessus." + string(rand(),rand(), rand()), port:port);
if ( res ) exit(0);

res = is_cgi_installed_ka(item:"/servlet/com.unify.servletexec.UploadServlet", port:port);
if(res)
{
 security_hole(port);
}

