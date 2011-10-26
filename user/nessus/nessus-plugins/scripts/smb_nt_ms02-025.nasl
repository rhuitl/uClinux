#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11143);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-b-0002"); 
 script_bugtraq_id(4881);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2002-0368");
 name["english"] = "Exchange 2000 Exhaust CPU Resources (Q320436)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to cause a DoS against the Mail Server.

Description :

The remote host is running Exchange Server 2000. The remote
version of this software contains a flaw wich may allow an
attacker to cause a denial of service.

To cause the DoS, the attacker needs to send a mail with 
malformed attributes.

Solution : 

Microsoft has released a set of patches for Exchange 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-025.mspx

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q320436, DOS on Exchange 2000";

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


server = hotfix_check_nt_server();
if (!server) exit (0);

version = get_kb_item ("SMB/Exchange/Version");
if (!version || (version != 60)) exit (0);

sp = get_kb_item ("SMB/Exchange/SP");
if (sp && (sp >= 3)) exit (0);

if (is_accessible_share())
{
 path = get_kb_item ("SMB/Exchange/Path") + "\bin";
 if ( hotfix_is_vulnerable (os:"5.0", file:"Exprox.dll", version:"6.0.5770.91", dir:path) )
   security_warning (get_kb_item("SMB/transport"));
 hotfix_check_fversion_end();
}
else if (hotfix_missing (name:"320436") > 0 )
 security_warning(get_kb_item("SMB/transport"));
