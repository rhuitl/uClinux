#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10433);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:" 2000-t-0005");
 script_bugtraq_id(1236);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0305");
 name["english"] = "NT IP fragment reassembly patch not applied (jolt2)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote host

Description :

The hotfix for the 'IP Fragment Reassembly' vulnerability has not
been applied on the remote Windows host.

This vulnerability allows an attacker to send malformed packets
which will hog this computer CPU to 100%, making it nearly 
unusable for the legitimate users.

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms00-029.mspx

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q259728 is installed";
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


if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q259728") > 0 ) 
	{
	  security_warning(get_kb_item("SMB/transport"));
	}

