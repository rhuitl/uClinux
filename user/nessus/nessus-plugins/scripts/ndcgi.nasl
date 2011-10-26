#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11730);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2001-0922");
 script_bugtraq_id(3583); 
 
 name["english"] = "ndcgi.exe vulnerability";
 name["francais"] = "ndcgi.exe vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The file ndcgi.exe exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.

Solution : remove it from /cgi-bin.
More info can be found at: http://marc.theaimsgroup.com/?l=bugtraq&m=100681274915525&w=2

*** As Nessus solely relied on the existence of the ndcgi.exe file, 
*** this might be a false positive


Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the ndcgi.exe file";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

no404 = get_kb_item("www/no404/" + port );

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/ndcgi.exe"), port:port)) {
   	if(no404 && is_cgi_installed_ka(item:string(dir, "/nessus" + rand() + ".exe"), port:port)) exit(0);
  	flag = 1;
  	directory = dir;
  	break;
  }
}
 
if (flag) security_hole(port);
