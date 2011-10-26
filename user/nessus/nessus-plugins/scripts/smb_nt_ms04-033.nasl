#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15458);
 script_bugtraq_id(11373);
 script_cve_id("CVE-2004-0846");

 script_version("$Revision: 1.9 $");
 name["english"] = "Microsoft Excel Code Execution (886836)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Excel.

Description :

The remote host has a version of Microsoft Excel which is vulnerable to 
a code execution issue. An attacker may exploit this flaw to execute
arbitrary code on the remote host with the privileges of the user
opening the file.

To exploit this flaw, an attacker would need to send a malformed Excel
file to a victim on the remote host and wait for him to open it.

Solution : 

Microsoft has released a set of patches for Excel 2000 and 2002:

http://www.microsoft.com/technet/security/bulletin/ms04-033.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 886836 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Excel/Version");
 exit(0);
}

port = get_kb_item("SMB/transport");
v = get_kb_item("SMB/Office/Excel/Version");
if ( v )
{
 
 if ( ereg(pattern:"^9\.", string:v) )
 {
  # Excel 2000 - fixed in 9.0.0.8924
  last = ereg_replace(pattern:"^9\.0*0(\.0*0)*\.([0-9]*)$", string:v, replace:"\2");
  if ( int(last) < 8924 ) { security_hole(port); exit(0); }
 }
 
 if ( ereg(pattern:"^10\.", string:v ) )
 {
  # Excel 2002 - fixed in 10.0.6501.0 (fixed in SP3 and version 10.0.6713.0)
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6501){ security_hole(port); exit(0); }
 }
}
