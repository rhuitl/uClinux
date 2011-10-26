#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15934);
 script_cve_id("CVE-2004-2496");
 script_bugtraq_id(11877);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12350");
 }
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "OpenText FirstClass HTTP Daemon Search DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running OpenText FirstClass, a web based
unified messaging system.

The remote version of this software is vulnerable to an unspecified
Denial of Service attack which may allow an attacker to disable this
service remotely.

See also : http://archives.neohapsis.com/archives/fulldisclosure/2004-12/0321.html
Solution : Upgrade to a version newer than FirstClass OpenText 8.0.0
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for FirstClass";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(banner)
{ 
  if(egrep(pattern:"^Server: FirstClass/([0-7]\.|8\.0[^0-9])", string:banner))
   	security_warning(port);
}
