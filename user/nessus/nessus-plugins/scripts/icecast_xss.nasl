#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref:  Markus Wörle
#
# This script is released under the GNU GPL v2

if(description)
{
 script_id(14390);
 script_bugtraq_id(11021);
 script_cve_id("CVE-2004-0781");
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "ICECast XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server runs a version of ICECast which is as old as or older
than version 1.3.12.

This version is affected by a cross-site scripting vulnerability
in the status display functionality. This issue is due to a failure 
of the application to properly sanitize user-supplied input.

As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed 
in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication credentials 
as well as other attacks.

Solution : Upgrade to a newer version.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
		
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);

if("icecast/" >< banner &&
   egrep(pattern:"icecast/1\.3\.([0-9]|1[0-2])[^0-9]", string:banner))
      security_hole(port);
