#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10926);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0003");
 script_bugtraq_id(4158);
 script_version("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0052");
 name["english"] = "IE VBScript Handling patch (Q318089)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Local files can be retrieved through the web client.

Description :

The remote host is running a version of Internet Explorer which is vulnerable to 
a flaw which may allow an attacker to read local files on the remote host.

To exploit this flaw, an attacker would need to lure a victim on the remote
system into visiting a rogue website.

Solution : 

Microsoft has released a set of patches for the Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-009.mspx

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the IE VBScript Handling patch (Q318089) is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 script_exclude_keys("SMB/WinXP/ServicePack");
 exit(0);
}

# deprecated -> too old flaw -> FP
exit (0);
