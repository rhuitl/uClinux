#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11433);
 script_bugtraq_id(7145);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2003-0011");

 name["english"] = "Microsoft ISA Server DNS - Denial Of Service (MS03-009)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote proxy server.

Description :

A vulnerability in Microsoft ISA Server 2000  allows an attacker to 
cause a denial of service of the remote Winsock proxy service by 
sending a specially crafted packet which would cause 100% CPU 
utilization on the remote host and make it unresponsive.

Solution : 

Microsoft has released a set of patches for ISA Server 2000 :

http://www.microsoft.com/technet/security/bulletin/ms03-009.mspx

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ISA Server DNS HotFix SP1-256";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

if (is_accessible_share ())
{
 path = get_kb_item ("SMB/Microsoft/Fpc");
 if (!path)
   exit (0);

 if ( hotfix_check_fversion(path:path, file:"Issfltr.dll", version:"3.0.1200.256") == HCF_OLDER ) security_warning(port);

 hotfix_check_fversion_end();
}
else 
{
 #superseded by SP2
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
 if(fix) exit(0);

 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/256");
 if(!fix)security_warning(port);
}
