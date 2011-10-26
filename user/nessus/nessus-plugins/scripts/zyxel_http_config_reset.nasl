#
# (C) Tenable Network Security
#

if(description)
{
   script_id(15781);
   script_cve_id("CVE-2004-1540");
   script_bugtraq_id(11723);
   script_version ("$Revision: 1.7 $");
   
   name["english"] = "ZyXEL Prestige Router Configuration Reset";
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote host is a Zyxel router. 

There is a flaw in the remote version of the firmware this device is
running which may allow an attacker to take control of the remote host.

The page '/rpFWUpload.html' on the remote host is not authenticated. An
attacker may use it to reset the configuration of the remote device to
its factory state.

Solution : Contact ZyXEL for a patch.
Risk factor : High";

   script_description(english:desc["english"]);
 
   summary["english"] = "Determines if /rpFWUpload.html is world-readable";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
   script_family(english:"Misc.", francais:"Divers");
   script_dependencie("http_version.nasl");
   script_require_ports(80);
 
   exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
if ( ! port || port != 80 ) exit(0);

banner = get_http_banner(port:port);
if ( "ZyXEL-RomPager" >!< banner ) exit(0);

req = http_get(item:"/fpFWUpload.html", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if (!  res ) exit(0);
if ( egrep(pattern:'<INPUT TYPE="BUTTON" NAME="ResetDefault" VALUE=".*" onClick="ConfirmDefault()"></div></td></tr><tr>', string:res ) )
	security_hole(port);
