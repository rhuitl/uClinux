#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10835);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2001-0876", "CVE-2001-0877");
 script_bugtraq_id(3723);

 name["english"] = "Unchecked Buffer in Universal Plug and Play can Lead to System Compromise";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The Universal Plug and Play service on the remote host is prone to
denial of service and buffer overflow attacks. 

Description :

Using a specially-crafted NOTIFY directive, a remote attacker can
cause code to run in the context of the Universal Plug and Play, UPnP,
subsystem or possibly lead to a denial of service attack against the
affected host.  Note that under Windows XP, the UPnP subsystem
operates with SYSTEM privileges. 

Solution : 

Microsoft has released a set of patches for Windows 98, 98SE, ME, and XP :

http://www.microsoft.com/technet/security/bulletin/ms01-059.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of hotfix Q315000";

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


include("smb_hotfixes.inc");


if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"315000") > 0  )
  security_hole(port);
