#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10784);
 script_bugtraq_id(3410);
 script_cve_id("CVE-2001-0834");
 script_version ("$Revision: 1.16 $");
 
 script_name(english:"ht://Dig's htsearch potential exposure/dos");
 desc = "
The remote CGI htsearch allows the user to supply his own
configuration file using the '-c' switch, as in :

	/cgi-bin/htsearch?-c/some/config/file

This file is not displayed by htsearch. However, if an
attacker manages to upload a configuration file to the remote 
server, it may make htsearch read arbitrary files on the remote host.

An attacker may also use this flaw to exhaust the resources on the
remote host by specifying /dev/zero as a configuration file.

Solution: Upgrade to ht://Dig 3.1.6 or newer
(http://www.htdig.org/files/snapshots/)

Risk factor : High";

 script_description(english:desc);

 script_summary(english:"htsearch?-c/nonexistent");

 script_family(english:"CGI abuses", francais:"Abus de CGI");
  
 script_category(ACT_GATHER_INFO);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_copyright("Copyright (C) 2001 Renaud Deraison"); 
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 command = string(dir, "/htsearch?-c/nonexistent");
 req = http_get(item:command, port:port);
 buffer = http_keepalive_send_recv(port:port, data:req);
 if(buffer == NULL)exit(0);
 if("Unable to read configuration file '/nonexistent'" >< buffer)
 {
 	security_warning(port);
	exit(0);
 }
}

