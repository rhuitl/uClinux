#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18503);
 script_bugtraq_id(6962, 13970, 13969, 14009);
 script_version("$Revision: 1.4 $");
 name["english"] = "Opera Multiple Vulnerabilities (3)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera installed on the remote host is prone to a
security flaw wherein a malicious attacker can inject malicious data
into a URI.  Such an attack would require that the attacker be able to
coerce an Opera user into browsing to a malicious URI. 

Successful exploitation would result in the attacker gaining access to
confidential data (such as authentication cookies) or executing code
within the browser. 

Solution : Install Opera 8.01 or newer.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
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
  v2 = split(v, keep:FALSE, sep:'.');
  if(int(v2[0]) == 8 && int(v2[1]) == 0 )
    security_hole(get_kb_item("SMB/transport"));
}
