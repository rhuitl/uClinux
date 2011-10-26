#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11749);
 script_bugtraq_id(7683, 7685, 7690, 7691, 7692);
 
 script_version("$Revision: 1.5 $");
 
 name["english"] = "Vignette StoryServer TCL code injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Vignette StoryServer v6, a web interface
to Vignette's Content Management suite.

A flaw in this product may allow an attacker to inject
arbitrary code in this server.

*** Nessus could not determine the existence of this vulnerability
*** so this might be a false positive

Solution : Upgrade to Vignette 6.0.4 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote Vignette StoryServer"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
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
 if("Vignette StoryServer v6" >< res) 
 {
  security_hole(port);
 }
}


