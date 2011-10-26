#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(11872);
  script_version ("$Revision: 1.6 $");
# script_bugtraq_id();
# script_cve_id("");

 name["english"] = "ODBC tools check ";
 script_name(english:name["english"]);
 
 desc["english"] = "
ODBC tools are present on the remote host.

ODBC tools could allow a malicious user to hijack and redirect ODBC traffic, 
obtain SQL user names and passwords or write files to the local drive of a 
vulnerable server.

Example: http://target/scripts/tools/getdrvrs.exe

Solution: Remove ODBC tools from the /scripts/tools directory.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of ODBC tools";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002 David Kyger");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);



flag = 0;

warning = string("
Many Web servers ship with default CGI scripts which allow for ODBC access
and configuration. Some of these test ODBC tools are present on the remote 
web server.

These tools could allow a malicious user to hijack and redirect ODBC 
traffic, obtain SQL user names and passwords or write files to the 
local drive of a vulnerable server.

Example: http://target/scripts/tools/getdrvrs.exe

The following ODBC tools were found on the server:");




port = get_http_port(default:80);

if(get_port_state(port)) {

   fl[0] = "/scripts/tools/getdrvrs.exe";
   fl[1] = "/scripts/tools/dsnform.exe";
 
   for(i=0;fl[i];i=i+1) 
   { 
    if(is_cgi_installed_ka(item:fl[i], port:port)) 
	{
        warning = warning + string("\n", fl[i]); 
        flag = 1;
        }
   }
    if (flag > 0) {
	warning += string("Solution : Remove the specified ODBC tools from the /scripts/tools directory.\n");
        warning += string("Risk factor : High");
        security_hole(port:port, data:warning);
        } else {
          exit(0);
        }
}


