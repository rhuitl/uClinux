#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10615);
 script_bugtraq_id(2368);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0017");

 
 name["english"] =  "Malformed PPTP Packet Stream Vulnerability (Q283001)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A flaw in the remote PPTP implementation may allow an attacker to cause a denial
of service.

Description :

The hotfix for the 'Malformed PPTP Packet Stream' problem has not been applied.
This hotfix corrects a memory leak in Windows NT PPTP implementation which may 
cause it to use all the resources of the remote host.

An attacker may use this flaw by sending malformed PPTP packets to the remote
host until no more memory is available. This would result in a denial of service
of the remote service or the whole system.

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms01-009.mspx

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q283001 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q283001") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
