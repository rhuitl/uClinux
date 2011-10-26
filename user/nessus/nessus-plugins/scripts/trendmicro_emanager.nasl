#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11747);
 script_bugtraq_id(3327);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2001-0958");
 
 
 name["english"] = "Trend Micro Emanager software check";
 name["francais"] = "Trend Micro Emanager software check";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The Trend Micro Emanager software resides on this server.
Some versions of this software have vulnerable dlls.  If vulnerable, 
remote exploit is possible.  For more info, visit:
http://www.securityfocus.com/bid/3327

Solution : Remove this CGI or upgrade to the latest version of this software
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for certain Trend Micro dlls";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK); 
 
 
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

flag = flag2 = 0;
directory = "";

file[0] = "register.dll";
#file[1] = "ContentFilter.dll";
#file[2] = "SFNofitication.dll";
#file[3] = "TOP10.dll";
#file[4] = "SpamExcp.dll";
#file[5] = "spamrule.dll";

for (i=0; file[i]; i = i + 1) {
foreach dir (cgi_dirs()) {
   if ( "eManager" >< dir )  flag2 = 1;
   if(is_cgi_installed_ka(item:string(dir, "/", file[i]), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
}
}

if ( (! flag2) && (! flag) )  {
	dirs[0] = "/eManager/Email%20Management/";
	dirs[1] = "/eManager/Content%20Management/";
        for (i=0; dirs[i]; i = i + 1) {
		for (q=0; file[q] ; q = q + 1) {
			if(is_cgi_installed_ka(item:string(dirs[i], file[q]) , port:port)) {
				security_note(port);
				exit(0);
			}
   		}
	}	
 }

if (flag) security_note (port);
