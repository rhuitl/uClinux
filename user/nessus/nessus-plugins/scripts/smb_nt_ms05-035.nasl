#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18679);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2005-0564");
 script_bugtraq_id(14216);
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-B-0010");

 name["english"] = "Vulnerability in Word May Lead to Code Execution (903672)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Word.

Description :

The remote host is running a version of Microsoft Word
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue word file to 
a user of the remote computer and have it open it. Then a bug in
the font parsing handler would result in code execution.

Solution : 

Microsoft has released a set of patches for Word 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms05-035.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinWord.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Word/Version");
 script_require_ports(139, 445);
 exit(0);
}

port = get_kb_item("SMB/transport");


v = get_kb_item("SMB/Office/Word/Version");
if(!v)exit(0);
if(ereg(pattern:"^10\..*", string:v))
  {
  # Word 2002 - updated in 10.0.6764.0
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  if(middle != v && int(middle) < 6764 )security_hole(port);
  else
    set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB903672", value:TRUE);
  }
else if(ereg(pattern:"^9\..*", string:v))
{
 # Word 2000 - fixed in 9.00.00.8930
 sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
 if(sub != v && int(sub) < 8930)security_hole(port);
 else
    set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB903672", value:TRUE);
}
