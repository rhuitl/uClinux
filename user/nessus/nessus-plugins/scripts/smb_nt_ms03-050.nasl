#
# (C) Tenable Network Security
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms03-050.mspx

if(description)
{
 script_id(11920);
 script_bugtraq_id(8835, 9010);
 script_cve_id("CVE-2003-0820", "CVE-2003-0821");

 
 script_version("$Revision: 1.13 $");

 name["english"] = "Word and/or Excel may allow arbitrary code to run";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Office.

Description :

The remote host is running a version of Microsoft Word and/or Microsoft Excel
which are subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue word or excel
file to the owner of this computer and have it open it. Then the
macros contained in the word file would bypass the security model
of word, and would be executed.

Solution : 

Microsoft has released a set of patches for Office 97, 2000 and 2002 :

http://www.microsoft.com/technet/security/bulletin/ms03-050.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinWord.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Word/Version");
 exit(0);
}

port = get_kb_item("SMB/transport");

v = get_kb_item("SMB/Office/Excel/Version");
if ( v )
{
 if( ereg(pattern:"^8\.0", string:v) )
 {
  # Excel 97 - fixed in 8.0.1.9904
  if( ereg(pattern:"^8\.0*0\.0*0\.", string:v) )
  {
   security_hole(port);
   exit(0);
  }
  last = ereg_replace(pattern:"^8\.0*0\.0*1\.([0-9]*)", string:v, replace:"\1");
  if ( int(last) < 9904 ) { security_hole(port); exit(0); }
 }
 
 if ( ereg(pattern:"^9\.", string:v) )
 {
  # Excel 2000 - fixed in 9.0.08216
  last = ereg_replace(pattern:"^9\.0*0\.0*0\.(.*)", string:v, replace:"\1");
  if ( int(last) < 8216 ) { security_hole(port); exit(0); }
 }
 
 if ( ereg(pattern:"^10\.", string:v ) )
 {
  # Excel 2002 - fixed in 10.0.5815.0
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 5815){ security_hole(port); exit(0); }
 }
}

v = get_kb_item("SMB/Office/Word/Version");
if(!v)exit(0);
if(ereg(pattern:"^10\..*", string:v))
  {
  # Word 2002 - updated in 10.0.5815.0
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 5815)security_hole(port);
  }
else if(ereg(pattern:"^9\..*", string:v))
{
 # Word 2000 - fixed in 9.00.00.8216
 sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 8216)security_hole(port);
}
else if(ereg(pattern:"^9\..*", string:v))
{
 # Word 97 - fixed in 8.0.0.9716
 sub =  ereg_replace(pattern:"^8\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 9716)security_hole(port);
}
