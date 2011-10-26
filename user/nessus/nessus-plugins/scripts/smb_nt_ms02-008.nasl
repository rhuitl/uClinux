#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10866);
 script_bugtraq_id(3699);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2002-0057");
 name["english"] = "XML Core Services patch (Q318203)";
 
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

http://www.microsoft.com/technet/security/bulletin/ms02-008.mspx

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the XML Core Services patch Q318202/Q318203 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#deprecated -> FP
exit(0);