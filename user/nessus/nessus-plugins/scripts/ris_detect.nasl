# This script was written by Jeff Adams <jadams@netcentrics.com>;
#
#
if(description)
{
 script_id(12231);
 script_version("$Revision: 1.2 $");
 name["english"] = "RIS Installation Check";
 script_name(english:name["english"]);
 desc["english"] = "
This plugin checks if the equipment was installed via RIS.

Risk factor : None";

 script_description(english:desc["english"]);
 summary["english"] = "Checks if the remote host was installed via RIS.";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Jorge Pinto And Nelson Gomes");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access", "SMB/transport");
 script_require_ports(139, 445);
 script_require_keys("SMB/WindowsVersion");
 exit(0);
}


include("smb_nt.inc");

services = get_kb_item("SMB/registry_access");
if ( ! services ) exit(-2);

port = kb_smb_transport();
if(!port)port = 139;


#---------------------------------
# My Main
#---------------------------------

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
item = "SourcePath";
value = registry_get_sz(key:key, item:item);

if(!value) {
        exit(-1);
}

if( match(string:value, pattern:'*RemInst*')  ){
        report = "The remote host was installed using RIS (Remote Installation Service).";
        security_note(port:port, data:report);
        exit(1);
}

exit(0);
