#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
#
# Date: Mon, 12 May 2003 11:41:37 -0400
# From: "@stake Advisories" <advisories@atstake.com>
# User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.3a)
# Subject: [VulnWatch] Apple AirPort Administrative Password Obfuscation (a051203-1)


if(description)
{
 script_id(11620);
 script_bugtraq_id(7554);
 script_cve_id("CVE-2003-0270");
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Airport Administrative Port";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is an Apple Airport Wireless Access Point which
can be administrated on top of TCP port 5009.

There is a design flaw in the administrative protocol which makes
the clients which connect to this port send the password
in plain text (although slightly obsfuscated).

An attacker who has the ability to sniff the data going to this
device may use this flaw to gain its administrative password and
gain its control. Since the airport base station does not keep any
log, it will be difficult to determine that administrative access
has been stolen.

Solution : Block incoming traffic to this port, and only administer
this base station when connected to it using a cross-over ethernet
cable.

Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Connects to port 5009 and says 'Hello'";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes");
 script_require_ports(5009);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = 5009;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);
req = "acpp" + crap(data:raw_string(0), length:124);
send(socket:soc, data:req);
r = recv(socket:soc, length:128);
if(!r)exit(0);
if("acpp" >< r && r != req){
	security_warning(port);
	register_service(port:5009, proto:"apple-airport-admin");
	}
