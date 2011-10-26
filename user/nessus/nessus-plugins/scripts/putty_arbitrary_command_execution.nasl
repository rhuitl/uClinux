#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14262);
 script_cve_id("CVE-2003-0069");

 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8347");

 script_version("$Revision: 1.4 $");

 name["english"] = "PuTTY window title escape character arbitrary command execution";

 script_name(english:name["english"]);


 desc["english"] = "
PuTTY is a free SSH client.  

This version contains a flaw that may allow a malicious user to insert 
arbitrary commands and execute them. 
The issue is triggered when an attacker sends commands, 
preceded by terminal emulator escape sequences. 
It is possible that the flaw may allow arbitrary code execution 
resulting in a loss of integrity.

Solution : Upgrade to version 0.54 or newer
Risk factor : High";



 script_description(english:desc["english"]);

 summary["english"] = "Determine PuTTY version";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("putty_version_check.nasl");
 script_require_keys("SMB/PuTTY/version");

 exit(0);
}

version = get_kb_item("SMB/PuTTY/version");
if ( ! version ) exit(0);
if ( ereg(pattern:"^([0-4]|5\.[0-3]([^0-9]|$))", string:version) )
	security_hole(0);
