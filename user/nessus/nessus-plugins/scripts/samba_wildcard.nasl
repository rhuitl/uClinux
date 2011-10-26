#
# This script was written by Tenable Network Security
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(15705);
 script_bugtraq_id(11624, 11678);
 script_cve_id("CVE-2004-0930", "CVE-2004-0882");
 script_version ("$Revision: 1.4 $");
 name["english"] = "Samba Multiple Remote Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number, is vulnerable
to a remote Denial Of Service vulnerability and a remote buffer overflow.
The Wild Card DoS vulnerability may allow an attacker to make the remote
server consume excessive CPU cycles.
The QFILEPATHINFO Remote buffer overflow vulnerability may allow an attacker
to execute code on the server.

An attacker needs a valid account or enough credentials to exploit those
flaws.

Solution : upgrade to Samba 3.0.8
See also : http://us4.samba.org/samba/security/CAN-2004-0882.html
See also : http://us4.samba.org/samba/security/CAN-2004-0930.html
Risk factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks samba version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"], francais:family["francais"]);
 if ( !defined_func("bn_random"))
 	script_dependencie("smb_nativelanman.nasl");
 else
	script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-0930") ) exit(0);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 3\.0\.[0-7]$", string:lanman))security_hole(139);
}
