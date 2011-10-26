#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(11168);
 script_bugtraq_id(6210);
 script_cve_id("CVE-2002-1318");

 script_version ("$Revision: 1.6 $");
 name["english"] = "Samba Unicode Buffer Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number, has 
a bug in the length checking for encrypted password change
requests from clients. A client could potentially send an encrypted
password, which, when decrypted with the old hashed password could be
used as a buffer overrun attack on the stack of smbd. 

Solution : upgrade to Samba 2.2.7
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks samba version";
 summary["francais"] = "vérifie la version de samba";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smb_nativelanman.nasl");
 script_require_ports(139);
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 # Samba 2.2.2 to 2.2.6 is affected
 if(ereg(pattern:"Samba 2\.2\.[2-6][^0-9]*$",
 	 string:lanman))security_hole(139);
}
