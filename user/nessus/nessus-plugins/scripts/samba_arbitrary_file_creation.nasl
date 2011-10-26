#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10786);
 script_bugtraq_id(2928);
 script_cve_id("CVE-2001-1162");
 script_version ("$Revision: 1.10 $");
 name["english"] = "Samba Remote Arbitrary File Creation";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number,
is vulnerable to a remote file creation vulnerability.

This vulnerability allows an attacker to overwrite arbitrary
files by supplying an arbitrarily formed NetBIOS machine name
to this server, and to potentially become root on the remote
server.

An attacker do not need any privileges to exploit this flaw.

Solution : upgrade to Samba 2.0.10 or 2.2.0a
Risk factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "checks samba version";
 summary["francais"] = "vérifie la version de samba";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
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
 if(ereg(pattern:"Samba 2\.0\.[5-9][^0-9]*$",
 	 string:lanman))security_hole(139);
	 
 if(ereg(pattern:"Samba 2\.2\.0$", string:lanman))security_hole(139);
}
