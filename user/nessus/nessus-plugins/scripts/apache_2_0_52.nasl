#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14803);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2004-0811");
 script_bugtraq_id(11239);
 script_xref(name:"IAVA", value:"2004-t-0032");
 script_xref(name:"OSVDB", value:"10218");

 name["english"] = "Apache = 2.0.51";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Apache Web Server 2.0.51. It is reported that this 
version of Apache is vulnerable to an access control bypass attack. This 
issue occurs when using the 'Satisfy' directive. An attacker may gain 
unauthorized access to restricted resources if access control relies on this 
directive.

Solution : Upgrade to Apache 2.0.52
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 if ( defined_func("bn_random") )
  script_dependencie("fedora_2004-313.nasl", "gentoo_GLSA-200409-33.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-0811") ) exit(0);

include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.51", string:serv))
 {
   security_hole(port);
 }
