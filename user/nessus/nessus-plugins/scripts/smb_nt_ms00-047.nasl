#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10482);
 script_bugtraq_id(1514, 1515);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0673");
 name["english"] =  "NetBIOS Name Server Protocol Spoofing patch";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to spoof the netbios name.

Description :

The hotfix for the 'NetBIOS Name Server Protocol Spoofing'
problem has not been applied.

This vulnerability allows a malicious user to make this
host think that its name has already been taken on the
network, thus preventing it to function properly as
a SMB server (or client).

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms00-047.mspx

See also :

http://support.microsoft.com/support/kb/articles/q299/4/44.asp

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q269239 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes.inc");

if  ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if  ( hotfix_missing(name:"Q299444") > 0 &&
      hotfix_missing(name:"Q269239") > 0 ) 
	{
	 security_warning(get_kb_item("SMB/transport"));
	}

