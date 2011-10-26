#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Ref: 
# From: Wichert Akkerman <wichert@wiggy.net>
# Subject: [SECURITY] [DSA-262-1] samba security fix
# Resent-Message-ID: <VvQa6C.A.oDH.Ng1c-@murphy>
# To: bugtraq@securityfocus.com
#
#
# [Waiting for more details to write something more effective]
#

if(description)
{
 script_id(11398);
 script_bugtraq_id(7106, 7107);
 script_cve_id("CVE-2003-0085", "CVE-2003-0086");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:095-03");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:016");

 script_version ("$Revision: 1.10 $");

 name["english"] = "Samba Fragment Reassembly Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number,
is vulnerable to a remote buffer overflow when receiving
specially crafted SMB fragment packets.

An attacker needs to be able to access at least one
share to exploit this flaw.

Solution : upgrade to Samba 2.2.8
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks samba version";
 summary["francais"] = "vérifie la version de samba";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.(0\..*|2\.[0-7][^0-9].*)", string:lanman))security_hole(139);
}
