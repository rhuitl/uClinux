#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11888);
 script_bugtraq_id(8826);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2003-0717");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-B-0017");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-a-0017");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0007");
 
 name["english"] = "Buffer Overrun in Messenger Service (828035)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows contains a Heap Overflow in the Messenger
service which may allow an attacker to execute arbitrary code on the
remote host with the SYSTEM privileges.

A series of worms (Gaobot, Agobot, ...) are known to exploit this
vulnerability in the wild.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-043.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q828035";

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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msgsvc.dll", version:"5.2.3790.90", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msgsvc.dll", version:"5.1.2600.1309", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msgsvc.dll", version:"5.1.2600.121", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Msgsvc.dll", version:"5.0.2195.6861", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Msgsvc.dll", version:"4.0.1381.7236", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Msgsvc.dll", version:"4.0.1381.33553", min_version:"4.0.1381.33000", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"KB828035") > 0  )
	security_hole(get_kb_item("SMB/transport"));

