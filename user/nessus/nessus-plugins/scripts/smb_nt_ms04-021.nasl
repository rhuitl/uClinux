#
# (C) Tenable Network Security
#
if(description)
{
 script_id(13639);
 script_bugtraq_id(10706);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2004-0205");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2004-B-0011");

 name["english"] = "IIS Redirection Vulnerability (841373) (registry check)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote web server.

Description :

The remote host has a version of IIS 4.0 which is vulnerable to a remote
flaw which may allow an attacker to take the control of the remote web server
and execute arbitrary commands on the remote host with the SYSTEM privileges.

Solution : 

Microsoft has released a set of patches for IIS 4.0 :

http://www.microsoft.com/technet/security/bulletin/ms04-021.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-021 over the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"4.0", file:"w3svc.dll", version:"4.2.788.1", dir:"\system32\inetsrv") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"KB841373") > 0 )	
	security_hole(get_kb_item("SMB/transport"));
