#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11215);
 script_bugtraq_id(6367);
 script_cve_id("CVE-2002-1256");
 script_version("$Revision: 1.13 $");

 name["english"] = "Flaw in SMB Signing Could Enable Group Policy to be Modified (329170)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to send unsigned SMB packets.

Description :

The remote version of Windows contains a flaw in the SMB signing
implementation. SMB signing is used to sign each packets sent 
between a client and a server to protect them against man in the
middle attacks.
If the Domain policy is configured to force usage of SMB signing
it is possible for an attacker to downgrade the communication to
disable SMB signing and try to launch man in the middle attacks.

Solution : 

Microsoft has released a set of patches for Windows XP and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-070.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 329170";

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
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srv.sys", version:"5.1.2600.1154", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Srv.sys", version:"5.1.2600.105", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.6110", dir:"\system32\drivers") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else
{
 if ( hotfix_check_sp(xp:2) == 0 && hotfix_missing(name:"896422") == 0 ) exit(0);
 if ( hotfix_missing(name:"Q329170") > 0 )
   security_warning(get_kb_item("SMB/transport"));
}
