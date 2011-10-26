#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: Jouko Pynnonen
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14250);
 script_bugtraq_id(9089);
if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"2854");
 
 script_version("$Revision: 1.5 $");

 name["english"] = "Opera skin zip file buffer overflow vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera on the remote host is vulnerable to a security
weakness. 

A problem has been identified in the handling of zipped skin files by
Opera.  Because of this, it may be possible for an attacker to gain
unauthorized access to a system using the vulnerable browser. 

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
We have determined that you are running Opera v." + v + ". 
This version is vulnerable to a security weakness.

A problem has been identified in the handling of zipped skin files by
Opera.  Because of this, it may be possible for an attacker to gain
unauthorized access to a system using the vulnerable browser. 

Solution : Upgrade to version 7.23 or newer
Risk factor : High";

  minor =  ereg_replace(pattern:"[0-9]\.([0-9]*)$", string:v, replace:"\1");
  major =  ereg_replace(pattern:"([0-9])\.[0-9]*$", string:v, replace:"\1");
  v2 = split(v, keep:FALSE, sep:'.');
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 23))
    security_hole(port:get_kb_item("SMB/transport"), data:report);
}
