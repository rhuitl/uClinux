#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11177);
 script_bugtraq_id(6371, 6372);
 script_version("$Revision: 1.18 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0002");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0008");
 script_cve_id("CVE-2002-1257","CVE-2002-1258","CVE-2002-1183","CVE-2002-0862");

 name["english"] = "Flaw in Microsoft VM Could Allow Code Execution (810030)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the VM.

Description :

The remote host is running a Microsoft VM machine which has a bug
in its bytecode verifier which may allow a remote attacker to execute
arbitrary code on this host, with the privileges of the SYSTEM.

To exploit this vulnerability, an attacker would need to send a malformed
applet to a user on this host, and have him execute it. The malicious
applet would then be able to execute code outside the sandbox of the VM.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-052.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q329077, Flaw in Microsoft VM JDBC";

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

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, xp:2, win2k:4) <= 0 ) exit(0);

version = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{08B0E5C0-4FCB-11CF-AAA5-00401C608500}/Version");
if (!version) exit(0);

v = split(version, sep:",", keep:FALSE);
if ( int(v[0]) < 5 ||
     ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) < 3807) )
{
 if ( hotfix_missing(name:"810030") > 0 )
   security_hole(get_kb_item("SMB/transport"));
}
