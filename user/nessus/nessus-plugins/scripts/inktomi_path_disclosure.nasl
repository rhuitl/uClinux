#
# This script is a mix between the work done by 
# Sarju Bhagat <sarju@westpoint.ltd.uk> and
# Martin O'Neal of Corsaire (http://www.corsaire.com)
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
#
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(12300);
 script_bugtraq_id(10275, 8050);
 script_cve_id("CVE-2004-0050");

 name["english"] = "Inktomi Search Physical Path Disclosure";
 script_name(english:name["english"]);

 script_version ("$Revision: 1.4 $");
 desc["english"] = "
This web server is running a vulnerable version of Inktomi Search

Certain requests using MS-DOS special file names such as nul can cause
a python error. The error message contains sensitive information such
as the physical path of the webroot. This information may be useful to
an attacker.

Solution : Upgrade to the latest version. This product is now developed i
by Verity and is called Ultraseek

See also : http://www.corsaire.com/advisories/c040113-001.txt 
Risk factor : Low";
 script_description(english:desc["english"]);

 summary["english"] = "Checks for a Inktomi Search vulnerability";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Westpoint Limited and Corsaire Limited");
  
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8765);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#
# The script code starts here
#

port = get_http_port(default:8765);
if(!get_port_state(port))exit(0);

# Check that the remote web server is UltraSeek, as 
# some other servers may crash the host when requested
# for a DOS device.
banner = get_http_banner(port:port);
if ( banner == NULL || "Server: Ultraseek" >!< banner ) exit(0);


req = http_get(item:"/nul", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if ( "httpsrvr.py:1033" >!< res ||
     "500 Internal Server Error" >!< res ) exit(0);

w = egrep(pattern:"directory", string:res);
if(w)
{
  webroot = ereg_replace(string:w, pattern:"^.*'(.*)'.*$", replace:"\1");
  if (webroot == w) exit(0);
  report = "
This web server is running a vulnerable version of Inktomi Search

Certain requests using MS-DOS special file names such as nul can cause
a python error. The error message contains sensitive information such
as the physical path of the webroot. This information may be useful to
an attacker.

The remote web root is : " + w + "

Solution :
 Upgrade to the latest version. This product is now devloped by Verity
 and is called Ultraseek

See also : http://www.corsaire.com/advisories/c040113-001.txt 
Risk factor : Low";
  security_warning(port:port, data:report);
}
