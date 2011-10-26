#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22334);
 script_cve_id("CVE-2006-0001");
 script_bugtraq_id(19951);
 script_version("$Revision: 1.4 $");

 name["english"] = "Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (910729)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Microsoft
Publisher.

Description :

The remote host is running a version of Microsoft Publisher
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it. Then a bug in
the font parsing handler would result in code execution.

Solution : 

Microsoft has released a set of patches for Publisher 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-054.mspx

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of MSPUB.exe";

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
# PowerPoint
#
v = get_kb_item("SMB/Office/Publisher/Version");
if ( v ) 
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Publisher 2000 - fixed in 9.00.00.8930
  sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
  if(sub != v && int(sub) < 8930 ) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Publisher XP - fixed in 10.0.6815.0
   middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6815) { security_warning(port); exit(0); }
 }
 else if(ereg(pattern:"^11\..*", string:v))
 {
  # Publisher 2003 - fixed in 11.0.8103.0
   middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 8103) { security_warning(port); exit(0); }
 }
}
