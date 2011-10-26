#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11992);
 script_bugtraq_id(9408);
 script_version("$Revision: 1.12 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-B-0002");
 script_cve_id("CVE-2003-0819");
 
 name["english"] = "Vulnerability in Microsoft ISA Server 2000 H.323 Filter(816458)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

A buffer overflow vulnerability in the H.323 filter of the Microsoft
ISA Server 2000 allows an attacker to execute arbitrary code on the
remote host.
An attacker can exploit this vulnerability by sending a specially crafted
packet to the remote ISA Server.

Solution :

Microsoft has released a set of patches for ISA Server Gold and SP1 :

http://www.microsoft.com/technet/security/bulletin/ms04-001.mspx

Risk factor : 

 Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q816458";

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

 if ( hotfix_check_fversion(path:path, file:"H323asn1.dll", version:"3.0.1200.291") == HCF_OLDER ) security_hole(port);

 hotfix_check_fversion_end();
}
else 
{
#superseded by SP2
fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
if(fix) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/291");
if(!fix)security_hole(port);
}
