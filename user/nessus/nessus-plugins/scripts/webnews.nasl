#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11732);
 script_bugtraq_id(4124);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0290");
 
 
 name["english"] = "Webnews.exe vulnerability";
 name["francais"] = "Webnews.exe vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that suffers from a buffer
overflow vulnerability. 

Description :

The remote host appears to be running WebNews, which offers web-based
access to Usenet news. 

Some versions of WebNews are prone to a buffer overflow when
processing a query string with an overly-long group parameter.  An
attacker may be able to leverage this issue to execute arbitrary shell
code on the remote host subject to the permissions of the web server
user id. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2002-02/0186.html

Solution : 

Apply the patch made released by the vendor on February 14th, 2002 if
running Webnews 1.1 or older. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the Webnews.exe file";
 
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/Webnews.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
}
 
if (flag) security_warning(port);
