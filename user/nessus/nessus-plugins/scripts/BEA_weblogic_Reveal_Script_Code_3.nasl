#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# and is based on BEA_weblogic_Reveal_source_code.nasl
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#



if(description)
{

script_id(11604);
script_bugtraq_id(1517);
script_version("$Revision: 1.6 $");
script_cve_id("CVE-2000-0683");

name["english"]="BEA WebLogic Scripts Server scripts Source Disclosure (3)";
script_name(english:name["english"], francais:name["francais"]);
desc["english"]="
BEA WebLogic may be tricked into revealing the source code of JSP scripts
by prefixing the path to the .jsp files by /*.shtml/


Solution: Use the official patch available at http://www.bea.com
or upgrade to a version newer than 5.1

Risk factor : Medium";
script_description(english:desc["english"]);


 

summary["english"]="BEA WebLogic may be tricked into revealing the source code of JSP scripts.";
summary["francais"]="BEA WebLogic peut etre utilisé dans le but d'afficher les sources des scripts.";
script_summary(english:summary["english"], francais:summary["francais"]);




script_category(ACT_GATHER_INFO);





script_copyright(english:"This script is (C) 2003 Renaud Deraison");


family["english"]="CGI abuses";
family["francais"]="Abus de CGI";
script_family(english:family["english"], francais:family["francais"]);
 

script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl");
script_require_ports("Services/www", 80);

exit(0);
}

include("http_func.inc");

function check(req, port)
{ 
soc = http_open_socket(port);
if(!soc) return(0); 

request = http_get(item:req, port:port); 
send(socket:soc, data:request);
response = http_recv(socket:soc);
http_close_socket(soc); 


#signature of Jsp.

signature = "<%=";

if (signature >< response) return(1);
 
return(0);
}

port = get_http_port(default:80);



if(!get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "WebLogic" >!< sig ) exit(0);

# Try with a known jsp file

files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(isnull(files))file = "/index.jsp";
else
 {
 files = make_list(files);
 file = files[0];
 }
 
if(check(req:string("/*.shtml/", file), port:port))security_warning(port);
 
