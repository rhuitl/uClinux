#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(16273);
 script_cve_id("CVE-2005-0320");
 script_bugtraq_id(12396);
 script_version ("$Revision: 1.4 $");

 script_name(english:"IceWarp Web Mail Multiple Flaws (3)");
 desc["english"] = "
The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform.

The remote version of this software is vulnerable to multiple 
input validation issues which may allow an attacker to compromise the
integrity of the remote host.

An attacker need a valid account on the webmail to perform an attack.

Solution : Upgrade to IceWarp Web Mail 5.3.3 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Check the version of IceWarp WebMail");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("icewarp_webmail_vulns.nasl");
 script_require_ports("Services/www", 32000);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:32000);

version = get_kb_item("www/" + port + "/icewarp_webmail/version");
if ( ! version ) exit(0);
if ( ereg(pattern:"IceWarp Web Mail ([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:version) )
	security_hole(port);
