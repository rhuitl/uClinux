#
# (C) Tenable Network Security
#
#
# MS01-011 was superceded by MS01-036

if(description)
{
 script_id(10619);
 script_bugtraq_id(2929);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2001-0502");
 
 name["english"] =  "LDAP over SSL could allow passwords to be changed (Q299687)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A bug in Windows 2000 may allow an attacker to change the password of a third 
party user.

Description :

The remote version of Windows 2000 contains a bug in its LDAP implementation
which fails to validate the permissions of a user requesting to change the
password of a third party user.

An attacker may exploit this vulnerability to gain unauthorized access to the
remote host.

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms01-036.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q287397 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}


include("smb_hotfixes.inc");

if ( hotfix_check_domain_controler() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"SP2SPR1") > 0 && hotfix_missing(name:"Q299687") > 0 )
	security_hole(get_kb_item("SMB/transport"));
