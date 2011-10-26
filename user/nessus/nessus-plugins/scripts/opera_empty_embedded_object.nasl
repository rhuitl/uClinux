#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14638);
 script_bugtraq_id(11090);
 
 script_version("$Revision: 1.3 $");

 name["english"] = "Opera Empty Embedded Object DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera installed on the remote host contains a flaw that
allows an attacker to crash this browser remotely. 

To exploit this flaw, an attacker would need to craft a rogue website
containing an embedded 'CCCC' object with an empty 'src' tag in it and
would need to lure a victim to visit it.

Solution : Install Opera 7.54 or newer.
Risk factor : Medium";

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
  minor =  ereg_replace(pattern:"[0-9]\.([0-9]*)$", string:v, replace:"\1");
  major =  ereg_replace(pattern:"([0-9])\.[0-9]*$", string:v, replace:"\1");
  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 54))security_warning(get_kb_item("SMB/transport"));
}
