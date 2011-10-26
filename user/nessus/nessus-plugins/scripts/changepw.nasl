#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11723);
 script_bugtraq_id(1256);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0401");
 
 
 name["english"] = "PDGSoft Shopping cart vulnerability";
 name["francais"] = "PDGSoft Shopping cart vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The executables 'redirect.exe' and/or 'changepw.exe' exist on this webserver.  
Some versions of these files are vulnerable to remote exploit.

An attacker can use this hole to gain access to confidential data
or escalate their privileges on the web server.

*** As Nessus solely relied on the existence of the redirect.exe or changepw.exe files,
*** this might be a false positive

Solution : remove them from cgi-bin or scripts folder.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PDGSoft Shopping cart executables";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
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

if (get_kb_item("www/" + port + "/no404") ) exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/changepw.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
   if(is_cgi_installed_ka(item:string(dir, "/redirect.exe"), port:port)) {
	flag = 1;
        directory = dir;
        break;
   }
}
 
if (flag) security_hole(port);
