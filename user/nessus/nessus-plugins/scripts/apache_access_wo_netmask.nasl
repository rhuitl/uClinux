#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
 
if (description) {
  script_id(14177);
  script_bugtraq_id(9829);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2003-0993");
  if (defined_func("script_xref")) {
    script_xref(name:"GLSA", value:"GLSA 200405-22");
    script_xref(name:"MDKSA", value:"MDKSA-2004:046");
    script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
    script_xref(name:"SSA", value:"SSA:2004-133-01");
    script_xref(name:"TSLSA", value:"TSLSA-2004-0027");
  }
 
  name["english"] = "Apache mod_access rule bypass";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running an Apache web server that may not properly handle
access controls.  In effect, on big-endian 64-bit platforms, Apache
fails to match allow or deny rules containing an IP address but not a
netmask. 

*****  Nessus has determined the vulnerability exists only by looking at
*****  the Server header returned by the web server running on the target.
*****  If the target is not a big-endian 64-bit platform, consider this a 
*****  false positive. 

Additional information on the vulnerability can be found at :

  - http://www.apacheweek.com/features/security-13
  - http://marc.theaimsgroup.com/?l=apache-cvs&m=107869603013722
  - http://issues.apache.org/bugzilla/show_bug.cgi?id=23850

Solution : Upgrade to Apache version 1.3.31 or newer.
Risk factor : Medium";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for Apache mod_access Rule Bypass Vulnerability";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2006 George A. Theall");

  family["english"] = "Web Servers";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl", "http_version.nasl");
  if ( defined_func("bn_random") ) script_dependencie("ssh_get_info.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

if ( report_paranoia < 2 ) exit(0);

uname = get_kb_item("Host/uname");
if ( uname )
{
 if ( egrep(pattern:"i.86", string:uname) ) exit(0);
}
host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: checking for mod_access Rule Bypass vulnerability on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check the web server's banner for the version.
banner = get_http_banner(port:port);
if (!banner) exit(0);
banner = get_backport_banner(banner:banner);

sig = strstr(banner, "Server:");
if (!sig) exit(0);
if (debug_level) display("debug: server sig = >>", sig, "<<.\n");

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-2][0-9]))", string:sig)) {
  security_warning(port);
}
