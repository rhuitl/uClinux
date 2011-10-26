#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22532);
 script_bugtraq_id(20344);
 script_cve_id("CVE-2006-2387", "CVE-2006-3431", "CVE-2006-3867", "CVE-2006-3875");
 script_version("$Revision: 1.3 $");

 name["english"] = "Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (924164)";

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

http://www.microsoft.com/technet/security/bulletin/ms06-059.mspx

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


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
  # Excel 2000 - fixed in 9.00.00.8950
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8950 ) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Excel XP - fixed in 10.0.6816.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6816) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Excel 2003 - fixed in 11.0.8104.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8104) { security_warning(port); exit(0); }
 }
}

