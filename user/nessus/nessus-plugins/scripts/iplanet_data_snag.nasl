#
# (C) Tenable Network Security
#

if (description) {
 script_id(11856);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0007");
 script_bugtraq_id(6826);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2001-0327");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0012");
 
 
 name["english"] = "iPlanet unauthorized sensitive data retrieval";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote iPlanet webserver (according to it's version number) is vulnerable
to a bug wherein a remote user can retrieve sensitive data from memory 
allocation pools, or cause a denial of service against the server.

*** Since Nessus solely relied on the banner of this server,
*** (and iPlanet 4 does not include the SP level in the banner),
*** to issue this alert, this may be a false positive.

Solution : Update to iPlanet 4.1 SP7 or newer

More information : http://www.atstake.com/research/advisories/2001/a041601-1.txt

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for vulnerable version of iPlanet Webserver";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) Tenable Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/iplanet");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");



port = get_http_port(default:80);

mybanner = get_http_banner(port:port);
if(!mybanner)exit(0);

if(egrep(pattern:"^Server: *Netscape-Enterprise/(4\.[01][^0-9])", string:mybanner))security_hole(port);
