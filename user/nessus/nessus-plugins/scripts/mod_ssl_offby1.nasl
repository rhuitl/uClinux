#
# This script was written by Thomas Reinke <reinke@e-softinc.com>,
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11039);
 script_bugtraq_id(5084);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2002-0653");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2002:028");

 
 name["english"] = "mod_ssl off by one";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of mod_ssl which is
older than 2.8.10.

This version is vulnerable to an off by one buffer overflow
which may allow a user with write access to .htaccess files
to execute arbitrary code on the system with permissions
of the web server.

*** Note that several Linux distributions (such as RedHat)
*** patched the old version of this module. Therefore, this
*** might be a false positive. Please check with your vendor
*** to determine if you really are vulnerable to this flaw

Solution : Upgrade to version 2.8.10 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of mod_ssl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Thomas Reinke");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if ( report_paranoia < 2 ) exit(0);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 
 serv = strstr(banner, "Server");
 if("Apache/" >!< serv ) exit(0);
 if("Apache/2" >< serv) exit(0);
 if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

 if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.[0-9][^0-9])).*", string:serv))
 {
   security_hole(port);
 }
}
