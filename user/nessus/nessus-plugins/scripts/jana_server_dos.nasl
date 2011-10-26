#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15862);
 script_bugtraq_id(11780);
 script_version("$Revision: 1.1 $");
 name["english"] = "JanaServer Multiple DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the JanaServer which is vulnerable
to various denial of service vulnerabilities. 

An attacker may exploit these vulnerabilities by sending a malformed request
to the remote service and cause it to enter an infinite loop, thus refusing
connections and using 100% of the CPU of the remote host.

Solution : Upgrade to JanaServer 2.4.5 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of JanaServer";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
if ( egrep(pattern:"^Server: Jana-Server/([01]\.|2\.([0-3]\.|4\.[0-4][^0-9]))", string:banner) )
	security_warning(port);
