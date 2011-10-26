#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11622);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2002-1157");
 script_bugtraq_id(6029);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"2107");
 }
 
 name["english"] = "mod_ssl wildcard DNS cross site scripting vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of mod_ssl which is
older than 2.8.10.

This version is vulnerable to a flaw which may allow an
attacker to successfully perform a cross site scripting attack
under some circumstances.

*** Note that several Linux distributions (such as RedHat)
*** patched the old version of this module. Therefore, this
*** might be a false positive. Please check with your vendor
*** to determine if you really are vulnerable to this flaw

Solution : Upgrade to version 2.8.10 or newer
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of mod_ssl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);
port = get_http_port(default:80);


if(!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if("Apache/" >!< serv ) exit(0);
if("Apache/2" >< serv) exit(0);
if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.[0-9][^0-9])).*", string:serv))
{
   security_warning(port);
}
