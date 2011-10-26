#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21690);
 script_cve_id("CVE-2006-2492");
 script_bugtraq_id(18037);
 script_version("$Revision: 1.4 $");

 name["english"] = "Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (917336)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Microsoft Word.

Description :

The remote host is running a version of Microsoft Word
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it. Then a bug in
the font parsing handler would result in code execution.

Solution : 

Microsoft has released a set of patches for Word 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-027.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinWord.exe";

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
  # Word 2000 - fixed in 9.00.00.8943
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8943 ) { security_hole(port); exit(0); }
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Word XP - fixed in 10.0.6802.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6802) { security_hole(port); exit(0); }
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Word 2003 - fixed in 11.08026.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8026) { security_hole(port); exit(0); }
 }
}
