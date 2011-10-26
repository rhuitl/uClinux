#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15467);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0034");
 script_bugtraq_id(11380);
 script_cve_id("CVE-2004-0569");
 script_version("$Revision: 1.6 $");

 name["english"] = "Vulnerability in RPC Runtime Library Could Allow Information Disclosure and Denial of Service (873350)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote web server or retrieve sensitive information.

Description :
The remote Windows operating system contains a bug in RPC Runtime Library.

RPC is a protocol used by Windows to provide an inter-process communication
mechanism which allows a program running on one system to access services on
another one.

A bug affecting the implementation of this protocol may allow an attacker
to cause it to crash, thus resulting in a crash of the whole operating system,
or to disclose random parts of the memory of the remote host.

An attacker may exploit this flaw to obtain sensitive information about the
remote host, by forcing it to disclose portions of memory containing passwords,
or to cause it to crash repeatedly, thus causing a denial of service for
legitimate users.

Solution : 

Microsoft has released a patch for Windows NT:

http://www.microsoft.com/technet/security/bulletin/ms04-029.mspx

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 873350 has been installed";

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

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"4.0", file:"Rpcrt4.dll", version:"4.0.1381.7299", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"873350") > 0  )
	security_hole(get_kb_item("SMB/transport"));

