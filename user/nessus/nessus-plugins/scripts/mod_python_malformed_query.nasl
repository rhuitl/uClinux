#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11937);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2003-0973");
 script_bugtraq_id(9129);
 script_xref(name:"OSVDB", value:"2885");
 
 name["english"] = "mod_python malformed query";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the Apache mod_python module
older than 2.7.9 or 3.0.4

These versions may be prone to a denial of service attacks when handling
malformed queries. 

Solution : Upgrade to a newer version.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Python";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);

 serv = strstr(banner, "Server");
 if(ereg(pattern:".*mod_python/(1.*|2\.([0-6]\..*|7\.[0-8])|3\.0\.[0-3][^0-9]).*", string:serv))
 {
   security_warning(port);
 }
}
