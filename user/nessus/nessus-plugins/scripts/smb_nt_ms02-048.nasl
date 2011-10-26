#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11144);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2002-0699");
 name["english"] = "Flaw in Certificate Enrollment Control Could Allow Deletion of Digital Certificates (Q323172)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to delete digital certificates on the remote host.

Description :

The remote host contains a version of the Certificate Enrollment
control which is vulnerable to a security flaw which may allow an
attacker to delete certificate.
To exploit this vulnerability an attacker must create a rogue web
server with SSL and lure the user to visit this site.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-048.mspx

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:N/A:P/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q323172, Certificate Enrollment Flaw";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Xenroll.dll", version:"5.131.3659.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Xenroll.dll", version:"5.131.3659.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Xenroll.dll", version:"5.131.3659.0", dir:"\system32") )
   security_note (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q323172") > 0 )
  security_note(get_kb_item("SMB/transport"));
