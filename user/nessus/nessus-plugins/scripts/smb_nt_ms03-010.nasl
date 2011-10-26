#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11485);
 script_bugtraq_id(6005);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0008");
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-1561");
 
 name["english"] = "Flaw in RPC Endpoint Mapper (MS03-010)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to disable a remote RPC service.

Description :

A flaw exists in the RPC endpoint mapper, which can be used by an attacker
to disable it remotely.

An attacker may use this flaw to prevent this host from working
properly

Solution : 

Microsoft has released a set of patches for the Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-010.mspx

There is no patch for NT4.

Microsoft strongly recommends that customers still using
Windows NT 4.0 protect those systems by placing them behind a
firewall which is filtering traffic on Port 135.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SP version";

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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rpcrt4.dll", version:"5.1.2600.1140", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Rpcrt4.dll", version:"5.1.2600.105", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Rpcrt4.dll", version:"5.0.2195.6106", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Rpcrt4.dll", version:"5.0.0.0", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"331953") > 0 && 
          hotfix_missing(name:"824146") > 0 && 
          hotfix_missing(name:"873333") > 0 && 
          hotfix_missing(name:"828741") > 0 &&
          hotfix_missing(name:"902400") > 0 &&
	  !((hotfix_check_sp (win2k:6) > 0) && ( hotfix_missing(name:"913580") <= 0 ) ) )
  security_warning(get_kb_item("SMB/transport"));
