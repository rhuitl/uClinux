#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: gollum <gollum@evilemail.com>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15396);
 script_bugtraq_id(2932);
 script_cve_id("CVE-2001-0784");
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"1883");
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "ICECast directory traversal flaw";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server runs a version of ICECast, an open source 
streaming audio server, which is version 1.3.10 or older.

These versions are affected by a directory traversal flaw.

An attacker could send specially crafted URL to view arbitrary files 
on the system.

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

if("icecast/" >< banner && 
   egrep(pattern:"icecast/1\.([012]\.|3\.[0-9][^0-9])", string:banner))
      security_hole(port);
