#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Ref: 
#
# Date: Sat, 22 Mar 2003 21:03:11 +0100 (CET)
# From: Stephan Lauffer <lauffer@ph-freiburg.de>
# To: tng-announcements@lists.dcerpc.org
# Cc: tng-technical@lists.dcerpc.org, <tng-users@lists.dcerpc.org>
# Subject: [ANNOUNCE] Samba-TNG 0.3.1 Security Release

#
# [Waiting for more details to write something more effective]
#

if(description)
{
 script_id(11442);
 script_bugtraq_id(7106, 7206);
 
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0085");

 name["english"] = "Samba TNG multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number,
is vulnerable to multiple flaws which may let an attacker
gain a root shell on this host


Solution : Upgrade to Samba TNG 0.3.1
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
 if(ereg(pattern:"Samba TNG-alpha$", string:lanman))security_hole(139);
}
