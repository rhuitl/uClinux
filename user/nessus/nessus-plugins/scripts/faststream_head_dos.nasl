#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15764);

 script_cve_id("CVE-2004-2534");
 script_bugtraq_id(11687);

 script_version("$Revision: 1.4 $");
 
 name["english"] = "FastStream Web Server HEAD DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the FastStream Web server
which is older or as old as version 7.1.

The remote version of this software does not close the connection when
an HTTP HEAD request is received with the keep-alive option set. An attacker
may exploit this flaw by sending multiple HEAD requests to the remote host,
thus consuming all its file descriptors until it does not accept connections
any more.

See also : http://users.pandora.be/bratax/advisories/b003.html

Solution : Upgrade to the newest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of FastStream NetFile";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie( "http_version.nasl" );
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);
if ( ! port || ! get_port_state(port) ) exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if ( egrep(pattern:"^Server: Fastream NETFile Web Server ([0-6]\..*)", string:banner) ) 
	security_warning(port);
 
