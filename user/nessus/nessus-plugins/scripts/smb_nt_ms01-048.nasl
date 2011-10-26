#
# This script was written by Michael Scheidell <scheidell@fdma.com>
# based on template from Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10806);
 script_bugtraq_id(3313);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2001-0662");
 
 name["english"] =  "RPC Endpoint Mapper can Cause RPC Service to Fail";
 
 script_name(english:name["english"]);
 	     
 
 desc["english"] = "
The hotfix for the 'RPC Endpoint Mapper Service on NT 4 has not been applied'
problem has not been applied.

Because the endpoint mapper runs within the RPC service itself, exploiting this
vulnerability would cause the RPC service itself to fail, with the attendant loss
of any RPC-based services the server offers, as well as potential loss of some COM
functions. Normal service could be
 restored by rebooting the server. 

Solution : See http://www.microsoft.com/technet/security/bulletin/ms01-048.mspx
Risk factor : High";


 script_description(english:desc["english"]);
 		    
 
 summary["english"] = "Determines whether the hotfix Q305399 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}


include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q305399") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));

