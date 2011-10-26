#
# Ref:
#  Date: Mon, 07 Apr 2003 12:13:24 -0400
#  From: "@stake Advisories" <advisories@atstake.com>
#  To: bugtraq@securityfocus.com
#  Subject: Vignette Story Server sensitive information disclosure (a040703-1)
#
# Special thanks to Ollie Whitehouse for his help in the writing of this plugin

if(description)
{
 script_id(11526);
 script_bugtraq_id(7296);
 script_cve_id("CVE-2002-0385");
 script_version("$Revision: 1.4 $");
 
 name["english"] = "Vignette StoryServer Information Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Vignette StoryServer, a web interface
to Vignette's Content Management suite.

A flaw in this product may allow an attacker to extract
information about the other users session and other 
sensitive information.


Solution : Vignette made available a patch at http://support.vignette.com/VOLSS/KB/View/1,,5360,00.html
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote Vignette StoryServer"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs)) dirs = make_list("");
else dirs = make_list(dirs);


foreach dir (dirs)
{
 req = http_get(item:string(dir , "/"), port:port);
 res = http_keepalive_send_recv(port:port, data:req); 
 if( res == NULL ) exit(0);
 if("Vignette StoryServer" >< res) 
 {
  if(egrep(pattern:"Vignette StoryServer [vV]?[0-4].*", string:res)){ security_warning(port); exit(0); }
  if("Vignette StoryServer v6" >< res)security_warning(port);
  exit(0);
 }
}


