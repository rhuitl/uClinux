#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(13844);
 script_bugtraq_id(10679, 10763, 10764);
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Multiple flaws in the Opera web browser (2)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera installed on the remote host is vulnerable to two
security issues :
 
- A cross domain frame loading vulnerability
- An unspecified vulnerability in the way it handles certificates

An attacker may exploit one of these flaws to impersonate a web server.

Solution : Install Opera 7.53 or newer
Risk factor : High";



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
  report = "
We have determined that you are running Opera v." + v + ". This version
is vulnerable to various security flaws which may allow an attacker to
execute arbitrary code on this host. 

To exploit these flaws, an attacker would need to set up a rogue website
and lure a user of this host visit it using Opera. He would then be able
to execute arbitrary code on this host.

Solution : Upgrade to version 7.53 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 53))
    security_hole(port:get_kb_item("SMB/transport"), data:report);
}
