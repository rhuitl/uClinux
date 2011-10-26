#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
#
# This check makes sure that the security rollup for Windows NT 4.0sp6a
# and Windows 2000 SP2 has been installed. Therefore, this plugin supercedes
# all the following MS advisories :
# MS99-003 MS99-019 MS99-022 MS99-029 MS99-039 MS99-046 
# MS99-047 MS99-053 MS99-055 MS99-056 MS99-057 MS99-058
# MS99-061 MS00-003 MS00-004 MS00-005 MS00-006 MS00-007
# MS00-008 MS00-018 MS00-019 MS00-021 MS00-023 MS00-024
# MS00-027 MS00-029 MS00-030 MS00-031 MS00-036 MS00-040
# MS00-044 MS00-047 MS00-052 MS00-057 MS00-060 MS00-063
# MS00-070 MS00-078 MS00-080 MS00-083 MS00-086 MS00-091
# MS00-094 MS00-095 MS00-100 MS01-003 MS01-004 MS01-008
# MS01-009 MS01-017 MS01-025 MS01-026 MS01-033
#
# MS00-077 MS00-079 MS01-004 MS01-007 MS01-011 MS01-013
# MS01-015 MS01-024 MS01-025 MS01-026 MS01-031 MS01-033
# MS01-035 MS01-036 MS01-037 MS01-040 MS01-041 MS01-043
# MS01-044 MS01-046 MS01-052 
#
# By extension, this covers :
#
# CVE-2000-0770
#

if(description)
{
 script_id(11366);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-t-0015");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-t-0017");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-b-0007");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-t-0001");
 script_bugtraq_id(3997);
 script_version("$Revision: 1.11 $");
 
 script_cve_id("CVE-2002-0018");
 
 name["english"] = "Trusting domains bad verification";
 
 script_name(english:name["english"]);
 
# Description taken from MS02-001
 desc["english"] = "
Trust relationships are created between Windows NT or Windows 2000 
domains to allow users in one domain to access resources in other domains 
without requiring them to authenticate separately to each domain. 
When a user in a trusted domain requests access to a resource in a trusting 
domain, the trusted domain supplies authorization data in the form of a list 
of Security Identifiers (SIDs) that indicate the user's identity and group 
memberships. The trusting domain uses this data to determine whether to 
grant the user's request.

A vulnerability exists because the trusting domain does not verify that 
the trusted domain is actually authoritative for all the SIDs in the 
authorization data. If one of the SIDs in the list identified a user 
or security group that is not in the trusted domain, the trusting domain 
would accept the information and use it for subsequent access control 
decisions. If an attacker inserted SIDs of his choice into the 
authorization data at the trusted domain, he could elevate his privileges 
to those associated with any desired user or group, including the Domain 
Administrators group for the trusting domain. This would enable the attacker 
to gain full Domain Administrator access on computers in the trusting domain. 

Solution : see http://www.microsoft.com/technet/security/bulletin/ms02-001.mspx
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of the relevant security fixes";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 && hotfix_missing(name:"SP2SRP1") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));

