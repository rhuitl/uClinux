#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(13657);
 script_bugtraq_id(10781);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"8191");
 script_cve_id("CVE-2004-0686");
 script_version ("$Revision: 1.7 $");
 name["english"] = "Samba Mangling Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number,
is vulnerable to a buffer overflow if the option 'mangling method' is
set to 'hash' in smb.conf (which is not the case by default).

An attacker may exploit this flaw to execute arbitrary commands on the remote
host.

Solution : upgrade to Samba 2.2.10 or 3.0.5
See also : http://us1.samba.org/samba/whatsnew/samba-2.2.10.html
See also : http://us1.samba.org/samba/whatsnew/samba-3.0.5.html
Risk factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks samba version";
 summary["francais"] = "vérifie la version de samba";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 if ( !defined_func("bn_random"))
 	script_dependencie("smb_nativelanman.nasl");
 else
	script_dependencie("smb_nativelanman.nasl", "freebsd_samba_304_4.nasl", "redhat-RHSA-2004-259.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-0686") ) exit(0);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.2\.[0-9]$", string:lanman))security_hole(139);
 else if(ereg(pattern:"Samba 3\.0\.[0-4]$", string:lanman))security_hole(139);
}
