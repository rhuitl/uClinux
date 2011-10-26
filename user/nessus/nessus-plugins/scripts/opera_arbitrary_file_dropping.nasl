#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11922);
 script_bugtraq_id(9019, 9021, 9089);
 
 script_version("$Revision: 1.6 $");

 name["english"] = "Opera Multiple MIME Type File Dropping Weaknesses";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

This version of Opera is vulnerable to a security flaw which may allow an 
attacker to drop arbitrary files with arbitrary names on this host.

To exploit these flaws, an attacker would need to set up a rogue website
and lure a user of this host visit it using Opera. He might then be able
to execute arbitrary code on this host.

Solution : Install Opera 7.22 or newer.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");
 exit(0);
}




v = get_kb_item("SMB/Opera/Version");
if(strlen(v))
{
  report = "
We have determined that you are running Opera v." + v + ". This version
is vulnerable to a security flaw which may allow an attacker to drop 
arbitrary files with arbitrary names on this host.

To exploit these flaws, an attacker would need to set up a rogue website
and lure a user of this host visit it using Opera. He would then be able
to execute arbitrary code on this host.

Solution : Upgrade to version 7.22 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 22))security_hole(port:get_kb_item("SMB/transport"), data:report);
}
