#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22031);
 script_bugtraq_id(18938, 18910, 18890, 18888, 18886, 18885, 18872);
 script_cve_id("CVE-2006-1301", "CVE-2006-1302", "CVE-2006-1304", "CVE-2006-1306", "CVE-2006-1308", "CVE-2006-1309", "CVE-2006-2388", "CVE-2006-3059");
 script_version("$Revision: 1.3 $");

 name["english"] = "Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (917285)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Microsoft Excel

Description :

The remote host is running a version of Microsoft Excel
which is subject to various flaws which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it with
Microsoft Excel.

Solution : 

Microsoft has released a set of patches for Excel 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-037.mspx

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Excel.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_ports(139, 445);
 exit(0);
}

port = get_kb_item("SMB/transport");



#
# Excel
#
v = get_kb_item("SMB/Office/Excel/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Excel 2000 - fixed in 9.00.00.8946
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8946 ) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Excel XP - fixed in 10.0.6809.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6809) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Excel 2003 - fixed in 11.0.8033.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8033) { security_warning(port); exit(0); }
 }
}

