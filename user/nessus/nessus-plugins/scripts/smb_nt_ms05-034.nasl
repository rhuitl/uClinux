#
# (C) Tenable Network Security
#


if(description)
{
 script_id(18487);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(13846, 13956, 13954);
 script_cve_id("CVE-2005-1215", "CVE-2005-1216");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-B-0013");
 
 name["english"] = "Cumulative Update for ISA Server 2000 (899753)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A user can elevate his privileges.

Description :

The remote host is missing a cumulative update for ISA Server 2000 which fixes
several security flaws which may allow an attacker to elevate his privileges.

Microsoft has released a set of patches for ISA Server 2000 :

http://www.microsoft.com/technet/security/bulletin/ms05-033.mspx

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 899753";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( !get_kb_item("SMB/registry_full_access") ) exit(0);

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

if (is_accessible_share ())
{
 path = get_kb_item ("SMB/Microsoft/Fpc");
 if (!path)
   exit (0);

 if ( hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"3.0.1200.430") == HCF_OLDER ) security_warning(port);

 hotfix_check_fversion_end();
}
else
{
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/430");
 if(!fix)security_warning(port);
}
