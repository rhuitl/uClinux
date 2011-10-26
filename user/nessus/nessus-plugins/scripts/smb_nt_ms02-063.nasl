#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11178);
 script_bugtraq_id(5807, 6067);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2002-1214");

 name["english"] = "Unchecked Buffer in PPTP Implementation Could Enable DOS Attacks (Q329834)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote system.

Description :

The remote version of Windows contains a flaw in his PPTP implementation.
If the remote host is configured to act as a PPTP server, a remote 
attacker can send a specially crafted packet to corrupt the kernel
memory and crash the remote system.

Solution : 

Microsoft has released a set of patches for Windows XP and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-063.mspx

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q329834, Unchecked Buffer in PPTP DOS";

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

if ( hotfix_check_sp(win2k:4, xp:2) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Raspptp.sys", version:"5.1.2600.1129", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Raspptp.sys", version:"5.1.2600.101", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Raspptp.sys", version:"5.0.2195.6076", dir:"\system32\drivers") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q329834") > 0 )
  security_warning(get_kb_item("SMB/transport"));

