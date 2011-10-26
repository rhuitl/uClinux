#
# Sarju Bhagat <sarju@westpoint.ltd.uk>
#
# GPLv2
#
# Fixes by Tenable:
#   - added CVE and OSVDB xrefs.

if(description)
{
 script_id(17348);
 script_cve_id("CVE-2004-2381");
 script_bugtraq_id(9917);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"4387");
 }
 script_version("$Revision: 1.4 $");
 name["english"] = "Jetty < 4.2.19 Denial of Service";

 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of Jetty which is older than
4.2.19.  The version is vulnerable to a unspecified denial of service. 

Solution : Upgrade to the latest version, or apply a patch.
Risk factor : Medium";



 script_description(english:desc["english"]);

 summary["english"] = "Checks for the version of Jetty";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2005 Westpoint Limited");
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

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner || "Jetty/" >!< banner )exit(0);

 serv = strstr(banner, "Server");
 if(ereg(pattern:"Jetty/4\.([01]\.|2\.([0-9][^0-9]|1[0-8]))", string:serv))
 {
   security_hole(port);
   exit(0);
 }
}
