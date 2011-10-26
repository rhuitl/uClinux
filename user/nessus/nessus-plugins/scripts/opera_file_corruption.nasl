#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: :: Operash ::
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14246);
 script_bugtraq_id(9279);
 
 script_version("$Revision: 1.5 $");

 name["english"] = "Opera relative path directory traversal file corruption vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera installed on the remote host is vulnerable to a
file corruption vulnerability.  This issue is exposed when a user is
presented with a file dialog, which will cause the creation of a
temporary file.  It is possible to specify a relative path to another
file on the system using directory traversal sequences when the
download dialog is displayed.  If the client user has write
permissions to the attacker-specified file, it will be corrupted. 

This could be exploited to delete sensitive files on the systems. 

Solution : Install Opera 7.23 or newer.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
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
is vulnerable to a security flaw which may allow an attacker to corrupt 
arbitrary files on this host.

Solution : Upgrade to version 7.23 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 23))security_hole(port:get_kb_item("SMB/transport"), data:report);
}
