#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15819);
 script_bugtraq_id(11729,11738);
 script_cve_id("CVE-2004-1067");
 script_version ("$Revision: 1.4 $");
  
 name["english"] = "Cyrus IMAPD Multiple Remote Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
According to its banner, the remote Cyrus IMAPD server is vulnerable to a 
remote buffer pre-authentication overflow as well as three post-authentication
overflows.

An attacker with or without a valid login could exploit those, and would 
be able to execute arbitrary commands as the owner of the Cyrus process.

Solution : Upgrade to Cyrus IMAPD 2.2.10 or newer.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a Cyrus IMAPD version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_family(english:"Gain a shell remotely");

 script_dependencie("cyrus_imap_prelogin_overflow.nasl");
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");
 exit(0);
}

port = get_kb_item("Services/imap");
if(!port) port = 143;

kb = get_kb_item("imap/" + port + "/Cyrus");
if ( ! kb ) exit(0);
if ( egrep(pattern:"^(1\..*|2\.([0-1]\..*|2\.[0-9][^0-9].*))", string:kb ))
	security_hole ( port );
