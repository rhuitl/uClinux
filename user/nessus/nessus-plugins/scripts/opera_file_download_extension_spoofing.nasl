#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: Secunia <http://www.secunia.com>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14247);
 script_cve_id("CVE-2004-2083");
 script_bugtraq_id(9640);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"3917");
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Opera web browser file download extension spoofing";

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera installed on the remote host contains a flaw that
may allow a malicious user to trick a user into running arbitrary
code. 

The issue is triggered when an malicious web site provides a file for
download, but crafts the filename in such a way that the file is
executed, rather than saved. 

It is possible that the flaw may allow arbitrary code execution
resulting in a loss of confidentiality, integrity, and/or
availability. 

Solution : Install Opera 7.50 or newer.
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

This version contains a flaw that may allow a malicious user 
to trick a user into running arbitrary code.
The issue is triggered when an malicious web site provides a file for download, 
but crafts the filename in such a way that the file is executed, rather than saved.

It is possible that the flaw may allow arbitrary code execution resulting in a 
loss of confidentiality, integrity, and/or availability.


Solution : Upgrade to version 7.50 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 50))
    security_hole(port:get_kb_item("SMB/transport"), data:report);
}
