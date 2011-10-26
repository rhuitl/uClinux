#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14254);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0023");
 script_bugtraq_id(10902);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0203");
 name["english"] = "Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server runs a script vulnerable to cross site scripting
attacks.

Description :

The remote host runs Outlook Web Access.

Outlook Web Access is a service for Microsoft Exchange, which provides
web-based email, calendaring and contact management to end users.

The remote version of Outlook Web Access is vulnerable to a cross-site
scripting vulnerability which may allow an attacker to execute arbitrary
java script in the security context of a victim using this service.

To exploit this flaw, an attacker would need to send a specially crafted
message to a victim using Outlook Web Access. When the victim reads the
message, the bug in Outlook Web Access triggers and cause the execution
of the script sent by the attacker.

Solution : 

Microsoft has released a set of patches for OWA for Exchange 5.5 :

http://www.microsoft.com/technet/security/bulletin/ms04-026.mspx

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-026 via the registry";

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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");

# now check for the patch
if ( hotfix_check_nt_server() <= 0 ) 
	exit(0);

version = get_kb_item ("SMB/Exchange/Version");

if (version == 55)
{
 if (!get_kb_item ("SMB/Exchange/OWA"))
   exit (0);

 if (is_accessible_share())
 {
  rootfile = get_kb_item("SMB/Exchange/Path");
  if ( ! rootfile ) exit(1);

  rootfile = rootfile + "\bin";
  # ms04-26 = 5.5.2658.1080, ms05-029 = 5.5.2658.34 ???
  if ( hotfix_check_fversion(path:rootfile, file:"cdo.dll", version:"5.5.2658.34") == HCF_OLDER ) security_note(port);

  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"842436") > 0 ) 
	security_note(get_kb_item("SMB/transport"));
}

