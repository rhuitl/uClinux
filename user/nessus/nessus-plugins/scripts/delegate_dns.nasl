#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21293);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2006-2072");
 script_bugtraq_id(17691);

 name["english"] = "DeleGate DNS Response Denial of Service Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A rogue DNS server may crash the remote proxy.

Description :

The remote host is running Delegate, a multi-application proxy.

The remote version of this software is vulnerable to a denial of service
when processing invalid DNS responses. An attacker may exploit this flaw to
disable this service remotely.

To exploit this flaw, an attacker would need to be able to inject malformed
DNS responses to the queries sent by the remote application.

Solution : 

Upgrade to DeleGate 8.11.6 or newer.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detetermines the version of the remote DeleGate proxy"; 

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 
 family["english"] = "Gain root remotely"; 
 
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if(!port) port = 8080;

if(get_port_state(port))
{
   banner = get_http_banner(port:port);
   if ( banner && "DeleGate/" >< banner )
   {
   serv = egrep(string:banner, pattern:"^Server:");
   if(ereg(pattern:"^Server:.*DeleGate/[0-7]\.|8\.([0-9]\.|10\.|11\.[0-5][^0-9])", string:serv, icase:TRUE)) security_note(port);
   }
}
