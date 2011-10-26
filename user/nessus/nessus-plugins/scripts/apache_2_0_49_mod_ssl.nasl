#
# (C) Tenable Network Security
#




if(description)
{
 script_id(12100);
 script_bugtraq_id(9826);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0113");
 name["english"] = "Apache mod_ssl denial of service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of Apache 2.x which is older 
than 2.0.49.

There is a bug in the module mod_ssl which ships with Apache 2.0.35 to 2.0.48
which makes it vulnerable to a remote denial of service.

An attacker may exploit this flaw by issuing malformed SSL commands when
connect to the remote host, and may therefore use it to prevent HTTPS from
working.

Solution : Upgrade to Apache/2.0.49 when it is available
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:443);
if(!get_port_state(port))exit(0);

transport = get_port_transport(port);

if ( ! ( t == ENCAPS_SSLv23 || 
	 t == ENCAPS_SSLv2 || 
	 t == ENCAPS_SSLv3 || 
	 t == ENCAPS_TLSv1) ) exit(0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(3[5-9]|4[0-8])", string:serv))
 {
   security_warning(port);
 }
