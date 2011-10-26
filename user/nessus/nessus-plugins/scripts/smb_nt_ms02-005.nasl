#
# (C) Tenable Network Security
#
#
#
# Also supercedes MS02-005, MS02-047, MS02-027, MS02-023, MS02-015, MS01-015
#
# 

if(description)
{
 script_id(10861);
 script_bugtraq_id(11388, 11385, 11383, 11381, 11377, 11367, 11366);
 if ( NASL_LEVEL >= 2191 ) script_bugtraq_id(10473, 8565, 9009, 9012, 9013, 9014, 9015, 9182, 9663, 9798, 12477, 12475, 12473, 12530, 13123, 13117, 13120);
 script_version("$Revision: 1.75 $");
 #script_cve_id("CVE-2004-0842", "CVE-2004-0727", "CVE-2004-0216", "CVE-2004-0839", "CVE-2004-0844", "CVE-2004-0843", "CVE-2004-0841", "CVE-2004-0845");
 if ( NASL_LEVEL >= 2191 ) script_cve_id("CVE-2003-0814", "CVE-2003-0815", "CVE-2003-0816", "CVE-2003-0817", "CVE-2003-0823", "CVE-2004-0549", "CVE-2004-0566", "CVE-2003-1048", "CVE-2001-1325", "CVE-2001-0149", "CVE-2001-0727", "CVE-2001-0875", "CVE-2001-1325", "CVE-2001-0149", "CVE-2001-0727", "CVE-2001-0875", "CVE-2001-0339", "CVE-2001-0002", "CVE-2002-0190", "CVE-2002-0026", "CVE-2003-1326", "CVE-2002-0027", "CVE-2002-0022", "CVE-2003-1328", "CVE-2002-1262", "CVE-2002-0193", "CVE-1999-1016", "CVE-2003-0344", "CVE-2003-0233", "CVE-2003-0309", "CVE-2003-0113", "CVE-2003-0114", "CVE-2003-0115", "CVE-2003-0116", "CVE-2003-0531", "CVE-2003-0809", "CVE-2003-0530", "CVE-2003-1025", "CVE-2003-1026", "CVE-2003-1027", "CVE-2005-0554", "CVE-2005-0555");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-a-0004");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0014");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0016");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-A-0006");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-b-0001");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0021");
 name["english"] = "IE 5.01 5.5 6.0 Cumulative patch (890923)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The Cumulative Patch for IE is not applied on the remote host.

Impact of vulnerability: Run code of attacker's choice. 

Solution : 

Microsoft has released a set of patches for the Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-020.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]); 
 summary["english"] = "Determines whether the hotfix 890923 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network SEcurity");
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

if ( hotfix_check_sp(xp:3, win2003:1, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.279", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1498", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2627", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1498", min_version:"6.0.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:3, file:"Mshtml.dll", version:"5.0.3539.2400", dir:"\system32") || 
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Mshtml.dll", version:"5.0.3826.2400", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
   hotfix_check_fversion_end();
 
 exit (0);
}
