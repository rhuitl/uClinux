#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14336);
 script_bugtraq_id(10997);
 
 script_version("$Revision: 1.4 $");
 name["english"] = "Opera Javascript Denial of Service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera installed on the remote host is vulnerable to a
remote denial of service. 

An attacker may cause the browser to crash by crafting a rogue HTML
page containing a specific JavaScript command. 

Solution : Install Opera 7.24 or newer.
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
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 24))
    security_warning(get_kb_item("SMB/transport"));
}
