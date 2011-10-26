#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14235);
 script_cve_id("CVE-2004-2491");
 script_bugtraq_id(10810, 10517);

 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8317"); 

 script_version("$Revision: 1.6 $");

 name["english"] = "Opera web browser URI obfuscation";

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera installed on the remote host is vulnerable to a
flaw wherein a remote attacker can obscure the URI, leading the user
to believe that he/she is accessing a trusted resource. 

To exploit this issue, an attacker would need to set up a rogue web
site, then entice a local user to visit the site.  Successful
exploitation would enable the attacker to execute arbitrary code on
this host. 

See also : http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1056.html
Solution : Install Opera 7.54 or newer

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check version of Opera for URI obfuscation bug";

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
  v2 = split(v, sep:".", keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 53))
	security_hole(get_kb_item("SMB/transport"));
}
