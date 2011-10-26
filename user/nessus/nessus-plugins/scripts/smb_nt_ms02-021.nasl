#
# (C) Tenable Network Security
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms02-021.mspx

if(description)
{
 script_id(11325);
 script_bugtraq_id(4397);
 script_cve_id("CVE-2002-1056");
 
 script_version("$Revision: 1.16 $");

 name["english"] = "Word can lead to Script execution on mail reply";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Word.

Description :

Outlook 2000 and 2002 provide the option to use Microsoft Word as 
the e-mail editor when creating and editing e-mail in RTF or HTML.

There is a flaw in some versions of Word which may allow an attacker
to execute arbitrary code when the user replies to a specially
formed message using Word.

An attacker may use this flaw to execute arbitrary code on this host.

Solution : 

Microsoft has released a set of patches for Office 2000 and 2002 :

http://www.microsoft.com/technet/security/bulletin/ms02-021.mspx

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinWord.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms02-031.nasl");
 script_require_keys("SMB/Office/Word/Version");
 exit(0);
}



v = get_kb_item("SMB/Office/Word/Version");

if(strlen(v))
{
 if(ereg(pattern:"^9\..*", string:v))
 {
  # Word 2000 - patched in WinWord 9.0.6328
  middle =  ereg_replace(pattern:"^9\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  minor =   ereg_replace(pattern:"^9\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
  if(middle == 0 && minor < 6328)security_warning(port);
 }
 else if(ereg(pattern:"^10\..*", string:v))
 {
  # Word 2002 - updated in 10.0.4009.3501
  
  middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
  minor  =  ereg_replace(pattern:"^10\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
  if(middle < 4009)security_warning(port);
  else if(middle == 4009 && minor < 3501)security_warning(port);
 }
}
