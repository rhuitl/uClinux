#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15714);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0037");
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0892");
 
 name["english"] = "ISA Server 2000 and Proxy Server 2.0 Internet Content Spoofing (888258)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to spoof the content of the remote proxy server.

Description :

The remote host is running ISA Server 2000, an HTTP proxy. The
remote version of this software is vulnerable to content spoofing
attacks.
An attacker may lure a victim to visit a malicious web site and
the user could believe is visiting a trusted web site.

Solution : 

Microsoft has released a set of patches for ISA Server 2000 :

http://www.microsoft.com/technet/security/bulletin/ms04-039.mspx

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:I)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q888258";

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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");

if ( !get_kb_item("SMB/registry_full_access") ) exit(0);

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

if (is_accessible_share ())
{
 path = get_kb_item ("SMB/Microsoft/Fpc");
 if (!path)
   exit (0);

 if ( hotfix_check_fversion(path:path, file:"wspsrv.exe", version:"3.0.1200.408") == HCF_OLDER ) security_warning(port);

 hotfix_check_fversion_end();
}
else
{
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
 if(!fix)security_warning(port);
}
