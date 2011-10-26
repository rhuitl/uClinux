#
#  (C) Tenable Network Security
#

if(description)
{
 script_id(15820);
 script_cve_id("CVE-2004-1541");
 script_bugtraq_id(11731);
 script_version("$Revision: 1.5 $");

 name["english"] = "Van Dyke SecureCRT Remote Command Execution Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a vulnerable version of SecureCRT, a
SSH/Telnet client built for Microsoft Windows operation systems.

It has been reported that SecureCRT does not safely check the protocol
handler. As a result, an attacker may be able to exploit it by setting
up a malicious SMB share.

Solution : Upgrade to SecureCRT 4.1.9 or newer.
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of SecureCRT";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}


version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/VanDyke/SecureCRT/License/Version");
if ( ! version ) version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/VanDyke/SecureCRT/Evaluation License/Version");
if ( ! version ) exit(0);

if(egrep(pattern:"^4\.(0\..*|1\.[0-8][^0-9].*)", string:version))
  security_warning(port);
