#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11286);
 script_bugtraq_id(5478);
 script_cve_id("CVE-2002-0974");
 
 script_version("$Revision: 1.8 $");

 name["english"] = "Flaw in WinXP Help center could enable file deletion";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary files can be deleted on the remote host through the web client.

Description :

There is a security vulnerability in the remote Windows XP Help and Support
Center which can be exploited by an attacker to delete arbitrary file
on this host.

To do so, an attacker needs to create malicious web pages that must
be visited by the owner of the remote system.

Solution : 

Microsoft has released a set of patches for Windows XP and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-060.mspx

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:N/A:N/I:C/B:I)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q328940";

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


if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Helpctr.exe", version:"5.1.2600.101", dir:"\pchealth\helpctr\binaries") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q328940") > 0 )
  security_warning(get_kb_item("SMB/transport"));

