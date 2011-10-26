#
# Sarju Bhagat <sarju@westpoint.ltd.uk>
#
# GPLv2


if(description)
{
 script_id(19304);
 script_bugtraq_id(1290);
 script_cve_id("CVE-2000-0470");
 script_version("$Revision: 1.1 $");
 name["english"] = "Allegro Software RomPager 2.10 Denial of Service";


 script_name(english:name["english"]);
 desc["english"] = "

The remote host is running Allegro Software RomPager version 2.10, according
to its banner. This version is vulnerable to a denial of service when sending a
specifically crafted malformed request.

Solution : Upgrade to the latest version, or apply a patch.
Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Checks for version of Allegro Software RomPager";

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
 if(!banner || "Allegro" >!< banner )exit(0);

 serv = strstr(banner, "Server");
 if(ereg(pattern:"Allegro-Software-RomPager/2\.([0-9][^0-9]|10)", string:serv))
 {
   security_hole(port);
   exit(0);
 }
}
