#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11147);
 script_bugtraq_id(4387, 5874);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2002-0693", "CVE-2002-0694"); 

 name["english"] = "Unchecked Buffer in Windows Help Facility Could Enable Code Execution (Q323255)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host contains a version of the HTML Helpfacility ActiveX control
module which is vulnerable to a security flaw which may allow an attacker
to execute arbitrary code on the remote host by constructing a malicious
web page and entice a victim to visit this web page.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-055.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q323255, Unchecked Buffer in Windows Help facility";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q323255") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
