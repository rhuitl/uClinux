#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17208);
 script_bugtraq_id(12636);
 script_version ("$Revision: 1.2 $");
  
 name["english"] = "Cyrus IMAP Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
According to its banner, the remote Cyrus IMAP server is vulnerable to 
multiple buffer overflows.
 
An attacker may exploit these vulnerabilities to execute arbitrary
code on the remote host.

Solution : Upgrade to version 2.2.11 of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the banner of Cyrus IMAPd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Gain a shell remotely");

 script_dependencie("cyrus_imap_prelogin_overflow.nasl");	       		     
 script_require_ports("Services/imap", 143);

 exit(0);
}

#
# The script code starts here
#

include("imap_func.inc");
port = get_kb_item("Services/imap");
if(!port) port = 143;

banner = get_kb_item("imap/" + port + "/Cyrus");
if ( ! banner ) exit(0);
if(egrep(pattern:"^(1\.*|2\.0\.*|2\.1\.[1-9][^0-9]|2\.1\.1[01])[0-9]*$", string:banner))
    security_hole(port);
