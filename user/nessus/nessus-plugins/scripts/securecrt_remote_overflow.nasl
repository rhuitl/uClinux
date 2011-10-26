#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Kyuzo <ogl@SirDrinkalot.rm-f.net>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15822);
 script_cve_id("CVE-2002-1059");
 script_bugtraq_id(5287);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"4991");
 
 script_version("$Revision: 1.5 $");
  
 name["english"] = "SecureCRT SSH1 protocol version string overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a vulnerable version of SecureCRT, a
SSH/Telnet client built for Microsoft Windows operation systems.

It has been reported that SecureCRT contain a remote buffer overflow
allowing an SSH server to execute arbitrary command via a specially
long SSH1 protocol version string.

Solution : Upgrade to SecureCRT 3.2.2, 3.3.4, 3.4.6, 4.1 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of SecureCRT";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");

 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/VanDyke/SecureCRT/License/Version");
if ( ! version ) version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/VanDyke/SecureCRT/Evaluation License/Version");
if ( ! version ) exit(0);

if (egrep(pattern:"^(2\.|3\.([01]|2[^.]|2\.1[^0-9]|3[^.]|3\.[1-3][^0-9]|4[^.]|4\.[1-5][^0-9])|4\.0 beta [12]([^0-9]|$))", string:version))
  security_hole(kb_smb_transport());
