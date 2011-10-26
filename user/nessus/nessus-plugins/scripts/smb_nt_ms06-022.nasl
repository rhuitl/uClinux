#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21686);
 script_version("$Revision: 1.2 $");

 #script_cve_id("CVE-2006-2378");
 script_bugtraq_id(18394);

 name["english"] = "Vulnerability in ART Image Rendering Could Allow Remote Code Execution (918439)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web
client. 

Description :

The remote host is running a version of Windows which contains a flaw
in the Hyperlink Object Library. 

An attacker may exploit this flaw to execute arbitrary code on the
remote host. 

To exploit this flaw, an attacker would need to construct a malicious
hyperlink and lure a victim into clicking it. 

Solution : 

Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/Bulletin/MS06-022.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 918439";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


rootfile = hotfix_get_systemroot();
if(!rootfile) exit(0);

port = kb_smb_transport ();

if ( hotfix_check_sp(xp:3, win2003:2, win2k:5) <= 0 ) exit(0);

if (is_accessible_share())
{
 rootfile = rootfile + "\system32";
 if ( hotfix_check_fversion(path:rootfile, file:"Jgdw400.dll", version:"106.0.0.0") == HCF_OLDER ) security_hole(port);

   hotfix_check_fversion_end();
}
else
{
  if ( hotfix_missing(name:"918439") > 0  )
    security_hole(port);
}
