#
# (C) Tenable Network Security
# 

if(description)
{
 script_id(15771);
 script_cve_id("CVE-2004-1520");
 script_bugtraq_id(11675);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "ipswitch IMail Server Delete Command Buffer Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Ipswitch IMail which
is older than version 8.14.0.

The remote version of this software is vulnerable to a buffer overflow
when it processes the argument of the 'delete' command. An attacker
may exploit this flaw to execute arbitrary code on the remote host.

Solution : Upgrade to IMail 8.14 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of IMail web interface";
 summary["francais"] = "Vérifie la version de l'interface web de IMail";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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
if(ereg(pattern:"^Server:.*Ipswitch-IMail/([1-7]\..*|(8\.(0[0-9]?[^0-9]|1[0-3][^0-9])))", string:serv))
   security_hole(port);

