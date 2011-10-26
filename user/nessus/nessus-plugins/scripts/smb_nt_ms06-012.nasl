#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21078);
 script_cve_id("CVE-2005-4131", "CVE-2006-0028", "CVE-2006-0029", "CVE-2006-0030", "CVE-2006-0031", "CVE-2006-0009");
 script_bugtraq_id(15926, 16181, 17000, 17091, 17100, 17101, 17108);
 script_version("$Revision: 1.6 $");

 name["english"] = "Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (905413)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Microsoft Office.

Description :

The remote host is running a version of Microsoft Office
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it. Then a bug in
the font parsing handler would result in code execution.

Solution : 

Microsoft has released a set of patches for Word 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-012.mspx

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinWord.exe / Excel.exe";

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
# Word
#
v = get_kb_item("SMB/Office/Word/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Word 2000 - fixed in 9.00.00.8939
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8939 ) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Word XP - fixed in 10.0.6775.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6775) { security_warning(port); exit(0); }
 }
}

#
# Excel
#
v = get_kb_item("SMB/Office/Excel/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Excel 2000 - fixed in 9.00.00.8938
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8938 ) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Excel XP - fixed in 10.0.6789.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6789 ) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Excel 2003 - fixed in 11.0.8012.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8012) { security_warning(port); exit(0); }
 }
}

