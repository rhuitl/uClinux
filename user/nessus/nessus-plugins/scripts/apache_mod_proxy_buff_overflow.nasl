#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Georgi Guninski
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15555);
 script_bugtraq_id(10508);
 script_cve_id("CVE-2004-0492");
 script_version("$Revision: 1.7 $");

 name["english"] = "Apache mod_proxy content-length buffer overflow";

 script_name(english:name["english"]);

 desc["english"] = "
The remote web server appears to be running a version of Apache that is older
than version 1.3.32.

This version is vulnerable to a heap based buffer overflow in proxy_util.c
for mod_proxy. This issue may lead remote attackers to cause a denial of 
service and possibly execute arbitrary code on the server.

Solution: Don't use mod_proxy or upgrade to a newer version.
Risk factor: Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for version of Apache";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 if ( defined_func("bn_random") )
  script_dependencie("mandrake_MDKSA-2004-065.nasl", "redhat-RHSA-2004-244.nasl", "macosx_SecUpd20041202.nasl");

 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

if ( get_kb_item("CVE-2004-0492") ) exit(0);

port = get_http_port(default:80);
if(!port)exit(0);
if(!get_port_state(port))exit(0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.(3\.(2[6-9]|3[01])))([^0-9]|$)", string:serv))
 {
   security_warning(port);
   exit(0);
 }
