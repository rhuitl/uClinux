#
# (C) Tenable Network Security
# 

if(description)
{
 script_id(19252);
 script_bugtraq_id(14315, 14317);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Alt-N MDaemon Imap Multiple Buffer Overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Alt-N MDaemon, an SMTP/IMAP server for the
Windows operating system family. 

It is reported that versions up to and including 8.0.3 are prone to multiple 
buffer overflow vulnerabilities. 

An attacker may cause a denial of service or execute arbitrary code on the 
remote server. 

The attacker does not need credentials to exploit the flaw in CRAM-MD5/LOGIN
authenticate method.

Solution : Upgrade to MDaemon 8.0.4 or newer.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote version of MDaemon";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service2.nasl");	       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");
 exit(0);
}

#
# The script code starts here
#

include("imap_func.inc");

port = get_kb_item("Services/imap");
if(!port)port = 143;

banner = get_imap_banner ( port:port );
if ( ! banner ) exit(0);

if(egrep(pattern:"^\* OK .*IMAP4rev1 MDaemon ([0-7]\..*|8\.0\.[0-3]) ready", string:banner)) security_hole(port);
