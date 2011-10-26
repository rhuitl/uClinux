#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15712);
 script_bugtraq_id(11648,12407);
 script_version("$Revision: 1.4 $");

 name["english"] = "Firefox IMG Tag Multiple Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Firefox, an alternative web browser.

The remote version of this software contains a security issue which may
allow an attacker to determine existence of local files, cause a DoS and steal passwords (Windows only).

The security vulnerability is due to the fact that Firefox does not
handle correctly <IMG> tag.


Solution : Upgrade to Firefox 1.0.0
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Firefox";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_org_installed.nasl");
 exit(0);
}




fox = get_kb_item("Mozilla/Firefox/Version");
if (fox)
{
  if (ereg(pattern:"^0\.*", string:fox) )
     security_hole(0);
}
