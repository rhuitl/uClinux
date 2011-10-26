#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18114);
 script_bugtraq_id(13268);
 script_version("$Revision: 1.2 $");
 name["english"] = "SunOne Web Proxy Unspecified Remote Buffer Overflows";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the SunOne Web Proxy. This version is reported
vulnerable to a number of remote buffer overflow.  Alledgedly, successful
exploitation would result in the attacker executing arbitrary commands on
the remote SunOne Web Proxy server.

Solution : Upgrade to 3.6 SP7 or higher
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of SunOne Web Proxy";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80, 443);
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
 
if(ereg(pattern:"^Forwarded: .* \(Sun-ONE-Web-Proxy-Server/([0-2]\..*|3\.([0-5]\..*|6(\)|-SP[0-6])))", string:banner))
 {
   security_hole(port);
 }
