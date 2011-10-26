#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(15469);
 script_cve_id(
   "CVE-2004-1669", 
   "CVE-2004-1670", 
   "CVE-2004-1671", 
   "CVE-2004-1672", 
   "CVE-2004-1673", 
   "CVE-2004-1674"
 );
 script_bugtraq_id(11371);
 script_version ("$Revision: 1.6 $");

 script_name(english:"IceWarp Web Mail Multiple Flaws");
 desc["english"] = "
The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform.

The remote version of this software is vulnerable to multiple 
input validation issues which may allow an attacker to compromise the
integrity of the remote host.

Solution : Upgrade to IceWarp Web Mail 5.3.0 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Check the version of IceWarp WebMail");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 32000);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:32000);

if(!get_port_state(port))exit(0);

res = http_get_cache(item:"/mail/", port:port);
if ( res == NULL ) exit(0);
if ('Merak Email Server</A><BR>IceWarp Web Mail' >< res )
{
 version = egrep(pattern:"IceWarp Web Mail [0-9]\.", string:res );
 if ( ! version ) exit(0);
 version = ereg_replace(pattern:".*(IceWarp Web Mail [0-9.]*).*", string:version, replace:"\1");
 set_kb_item(name:"www/" + port + "/icewarp_webmail/version", value:version);
 if ( ereg(pattern:"IceWarp Web Mail ([0-4]\.|5\.[0-2]\.)", string:version) )
	security_hole(port);
}
