#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Karol Wiesek - iDEFENSE 
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15394);
 script_bugtraq_id(11216, 11281);
 script_cve_id("CVE-2004-0815");
 script_version ("$Revision: 1.7 $");
 name["english"] = "Samba Remote Arbitrary File Access";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Samba server, according to its version number, is vulnerable 
to a remote file access vulnerability.  


This vulnerability allows an attacker to access arbitrary files which exist
outside of the shares's defined path.

An attacker needs a valid account to exploit this flaw.

Solution : Upgrade to Samba 2.2.11 or 3.0.7
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks samba version";
 summary["francais"] = "vérifie la version de samba";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
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
 if(ereg(pattern:"Samba 2\.2\.([0-9]|10)[^0-9]*$",string:lanman))
   security_hole(139);
	 
 if(ereg(pattern:"Samba 3\.0\.[0-5]$", string:lanman))
   security_hole(139);
}
