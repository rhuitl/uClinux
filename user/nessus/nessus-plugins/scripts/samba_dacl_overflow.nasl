#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15985);
 script_bugtraq_id(11973);
 script_cve_id("CVE-2004-1154");
 script_version ("$Revision: 1.3 $");
 name["english"] = "Samba Directory ACL Integer Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number, is vulnerable to 
a remote buffer overrun resulting from an integer overflow vulnerability.

To exploit this flaw, an attacker would need to send to the remote host
a malformed packet containing hundreds of thousands of ACLs, which would
in turn cause an integer overflow resulting in a small pointer being allocated.

An attacker needs a valid account or enough credentials to exploit this
flaw.

Solution : Upgrade to Samba 3.0.10 when available
Risk factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks samba version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-1154") ) exit(0);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba ([0-2]\.|3\.0\.[0-9]$)", string:lanman))security_hole(139);
}
