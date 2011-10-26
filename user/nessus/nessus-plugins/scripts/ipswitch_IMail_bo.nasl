#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPL v2

if(description)
{
 script_id(14684);
 script_cve_id("CVE-2004-2422", "CVE-2004-2423");
 script_bugtraq_id(11106);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"9552");
   script_xref(name:"OSVDB", value:"9553");
   script_xref(name:"OSVDB", value:"9554");
 }
 script_version("$Revision: 1.5 $");
 
 name["english"] = "ipswitch IMail DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running IMail web interface.  This version contains 
multiple buffer overflows.

An attacker could use these flaws to remotely crash the service 
accepting requests from users, or possibly execute arbitrary code.

Solution : Upgrade to IMail 8.13 or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of IMail web interface";
 summary["francais"] = "Vérifie la version de l'interface web de IMail";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include ("http_func.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
if ( ! banner ) exit(0);
serv = egrep(string: banner, pattern: "^Server:.*");
if(ereg(pattern:"^Server:.*Ipswitch-IMail/([1-7]\..*|(8\.(0[0-9]?[^0-9]|1[0-2][^0-9])))", string:serv))
   security_hole(port);
