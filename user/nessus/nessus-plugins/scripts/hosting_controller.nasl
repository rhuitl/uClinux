#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11745);
 script_bugtraq_id(3808);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-0466");
 
 name["english"] = "Hosting Controller vulnerable ASP pages";
 name["francais"] = "Hosting Controller vulnerable ASP pages";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The Hosting Controller application resides on this server.  
This version is vulnerable to multiple remote exploits.  

At attacker may make use of this vulnerability and use it to
gain access to confidential data and/or escalate their privileges
on the Web server.

See http://archives.neohapsis.com/archives/bugtraq/2002-01/0039.html
for more information.

Solution : remove or update the software.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the vulnerable instances of Hosting Controller";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 
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

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

flag = 0;
directory = "";

file[0] = "statsbrowse.asp";
file[1] = "servubrowse.asp";
file[2] = "browsedisk.asp";
file[3] = "browsewebalizerexe.asp";
file[4] = "sqlbrowse.asp";

for (i=0; file[i]; i = i + 1) {
	foreach dir (cgi_dirs()) {
   		if(is_cgi_installed_ka(item:string(dir, "/", file[i]), port:port)) {
			req = http_get(item:dir + "/" + file[i] + "?filepath=c:" + raw_string(0x5C,0x26) + "Opt=3", port:port);
			res = http_keepalive_send_recv(port:port, data:req);
			if(res == NULL) exit(0);
		       if ( (egrep(pattern:".*\.BAT.*", string:res)) || (egrep(pattern:".*\.ini.*", string:res)) ) {
					security_hole(port);
					exit(0);
				}
			}
   		}
	}
