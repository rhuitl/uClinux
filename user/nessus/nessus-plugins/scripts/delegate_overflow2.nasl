#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPL v2
#
# Changes by Tenable Network Security:
#  - POP3 check
#

if(description)
{
 script_id(17599);
 script_version ("$Revision: 1.3 $");

 script_cve_id("CVE-2005-0861");
 script_bugtraq_id(12867);

 name["english"] = "Delegate Multiple Overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Delegate, a multi-application proxy.

The remote version of this software is vulnerable to multiple
remote buffer overflow vulnerabilities which may allow an attacker
to execute arbitrary code on the remote host.

This problem may allow an attacker to gain a shell on this computer.

Solution : Upgrade to version 8.10.3 of this product
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if DeleGate si vulnerable to buffer overflow flaw"; 

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 
 family["english"] = "Gain root remotely"; 
 
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl","find_service.nes");
 script_require_ports("Services/http_proxy", 8080, "Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if ( ! port ) port = 110;
if ( get_port_state(port) )
{
 banner = get_pop3_banner(port:port);
 if ( banner )
 {
  if ( egrep(pattern:"^\+OK Proxy-POP server \(Delegate/([0-7]\..*|8\.([0-9]\..*|10\.[0-2][^0-9])) by", string:banner) )
	security_hole(port);
  exit(0);
 }
}

port = get_kb_item("Services/http_proxy");
if(!port) port = 8080;

if(get_port_state(port))
{
   banner = get_http_banner(port:port);
   if ( banner )
   {
   #Server: DeleGate/8.11.1
   serv = strstr(banner, "Server");
   if(ereg(pattern:"^Server:.*DeleGate/[0-7]\.|8\.([0-9]\.|10\.[0-2][^0-9])", string:serv, icase:TRUE))
     security_hole(port);
   }
}
