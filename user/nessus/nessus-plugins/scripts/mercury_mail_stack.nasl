#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(15867);
 script_version ("$Revision: 1.4 $");

 script_cve_id("CVE-2004-1211");
 script_bugtraq_id(11775, 11788);
  
 name["english"] = "Mercury Mail Remote IMAP Stack Buffer Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Mercury Mail server, an IMAP server for
Windows operating systems.

It is reported that versions up to and including 4.01 are prone to
stack buffer overflow vulnerabilities. An authenticated attacker may
execute arbitrary code on the remote server. The attacker needs to
authenticate in order to exploit these vulnerabilities against the
IMAP server.

Solution : No solution at this time.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Mercury Mail";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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
if(!port) port = 143;

banner = get_imap_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^\* OK.*IMAP4rev1 Mercury/32 v([0-3]\..*|4\.(00.*|01[^b-z].*))server ready.*", string:banner))
{
  security_hole(port);
}    
