#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15774);
 script_cve_id("CVE-2004-2416");
 script_bugtraq_id ( 11666 );
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"11593");
 }
 script_version ("$Revision: 1.3 $");
 name["english"] = "CCProxy Logging Function Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running CCProxy, an application proxy supporting
many protocols (Telnet, FTP, WWW, and more...).

There is a buffer overflow in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host with
the privileges of the user running the proxy.

Solution : Upgrade to CCProxy 6.3 (when available) or disable this software
Risk Factor : High";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Detects CCProxy";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "Gain a shell remotely"; 
 
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/ccproxy-smtp");
 exit(0);
}

#
# The script code starts here
#
include("smtp_func.inc");
port = get_kb_item("Services/ccproxy-smtp");
if ( ! port ) exit(0);
banner = get_smtp_banner ( port:port);
if ( egrep(pattern:"CCProxy ([0-5]\.|6\.[0-2]) SMTP Service Ready", string:banner) )
	security_hole ( port );

