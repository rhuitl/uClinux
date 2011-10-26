#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22183);
 script_bugtraq_id(19319, 19404);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2006-3440", "CVE-2006-3441");

 name["english"] = "Vulnerability in DNS Resolution Could Allow Remote Code Execution (920683)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
DNS client.

Description :

The remote host is vulnerable to a buffer overrun in the DNS client service
which may allow an attacker to execute arbitrary code on the remote host
with the 'System' privileges.

To exploit this vulnerability, an attacker would need to set up a rogue
DNS server to reply to the client with a specially crafted packet.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-041.mspx

Risk factor : 

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 920683";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Dnsapi.dll", version:"5.2.3790.558", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Dnsapi.dll", version:"5.2.3790.2745", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Dnsapi.dll", version:"5.1.2600.1862", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Dnsapi.dll", version:"5.1.2600.2938", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Dnsapi.dll", version:"5.0.2195.7100", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"920683") > 0 )
	 security_hole(get_kb_item("SMB/transport"));


