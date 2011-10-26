#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: ned <nd@felinemenace.org>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15397);
 script_cve_id("CVE-2004-2027");
 script_bugtraq_id(10311);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"6075");
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "ICECast HTTP basic authorization DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server runs ICECast 2.0.0, an open source streaming audio 
server.

This version is affected by a remote denial of service.

An remote attacker could send specially crafted URL, with a long string
passed in an Authorization header that will result in a loss of availability 
for the service.

*** Nessus reports this vulnerability using only
*** information that was gathered.

Solution : Upgrade to a newer version.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check icecast version";
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
if (! banner ) exit(0);
if("icecast/" >< banner && egrep(pattern:"icecast/2\.0\.0[^0-9])", string:banner))
      security_hole(port);
