#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16125);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0001");
 script_version("$Revision: 1.9 $");
 script_bugtraq_id(12228);
 script_cve_id("CVE-2004-0897");
 name["english"] = "Indexing Service Code Execution (871250) (registry check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host contains a version of the Indexing Service which is
vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious query.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-003.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS05-003";

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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Query.dll", version:"5.2.3790.220", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Query.dll", version:"5.1.2600.1596", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Ciodm.dll", version:"5.0.2195.6981", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ((hotfix_check_sp (xp:2, win2k:5) > 0) &&
     (hotfix_missing(name:"920685") <= 0 ))
   exit(0);

 if ( hotfix_missing(name:"871250") > 0 )
   security_hole(get_kb_item("SMB/transport"));
}
