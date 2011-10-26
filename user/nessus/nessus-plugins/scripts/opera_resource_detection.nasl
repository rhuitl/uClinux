#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14346);
 script_cve_id("CVE-2004-1490");
 script_bugtraq_id(10961, 11883);
 
 script_version("$Revision: 1.8 $");

 name["english"] = "Opera Resource Detection"; 

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera on the remote host contains a flaw that allows an
attacker to determine the existence of files and directories on the
remote host. 

To exploit this flaw, an attacker would need to set up a rogue website
and lure a user of the remote host into visiting it with Opera. 

Solution : Install Opera 7.54 or newer.
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");
 exit(0);
}

v = get_kb_item("SMB/Opera/Version");
if(strlen(v))
{
  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 54))
    security_warning(get_kb_item("SMB/transport"));
}


