#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11534);
 script_bugtraq_id(7314);
 script_cve_id("CVE-2003-0110");
 script_version ("$Revision: 1.13 $");

 name["english"] = "Microsoft ISA Server Winsock Proxy DoS (MS03-012)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote proxy server.

Description :

A vulnerability in Microsoft Proxy Server 2.0 and ISA Server 2000 
allows an attacker to cause a denial of service of the remote Winsock
proxy service by sending a specially crafted packet which would cause
100% CPU utilization on the remote host and make it unresponsive.

Solution : 

Microsoft has released a set of patches for ISA Server 2000 :

http://www.microsoft.com/technet/security/bulletin/ms03-012.mspx

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ISA Server HotFix SP1-257";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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

 if ( hotfix_check_fversion(path:path, file:"W3proxy.exe", version:"3.0.1200.257") == HCF_OLDER ) security_warning(port);

 hotfix_check_fversion_end();
}
else 
{
 #superseded by MS04-039
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
 if(fix) exit(0);

 #superseded by SP2
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
 if(fix) exit(0);

 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/257");
 if(!fix)security_warning(port);
}
