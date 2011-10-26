#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopis :

An antivirus is installed on the remote host.

Description :

The remote host has an antivirus installed and running.
The remote antivirus engine and virus definitions are
up to date.

Risk factor : 

None";

if(description)
{
 script_id(16193);
 script_version("$Revision: 1.5 $");
 name["english"] = "Anti Virus Check";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 summary["english"] = "Checks that the remote has an Antivirus installed."; 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security"); 
 family["english"] = "Windows"; 
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl", "kaspersky_installed.nasl", "mcafee_installed.nasl", "nav_installed.nasl", "panda_antivirus_installed.nasl", "trendmicro_installed.nasl", "savce_installed.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}
include("smb_func.inc");

#==================================================================#
# Section 1. Report                                                #
#==================================================================#

port = kb_smb_transport();
if(!port)port = 139;

software = make_list(
  "Kaspersky",
  "McAfee",
  "Norton",
  "Panda",
  "TrendMicro",
  "SAVCE"
);

foreach av (software) {
  if (get_kb_item("Antivirus/" + av + "/installed")) {
    info = get_kb_item("Antivirus/" + av + "/description");
    if (info) {
      report = string (
        desc["english"],
        "\n\n",
        "Plugin output :",
        "\n\n",
        info
      );
      security_note(port:port, data:report);
      exit(0);
    }
  }
}
