#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: d3thStaR <d3thStaR@rootthief.com>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14248);
 script_cve_id("CVE-2004-1810");
 script_bugtraq_id(9869);
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Opera web browser large javaScript array handling vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The version of Opera on the remote host is vulnerable to an issue when
handling large JavaScript arrays. 

In particular, it is possible to crash the browser when performing
various operations on Array objects with 99999999999999999999999 or
0x23000000 elements. 

The crash is due to a segmentation fault and may be indicative of an
exploitable memory corruption vulnerability, possibly resulting in
arbitrary code execution. 

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

This version is vulnerable to an issue when handling large JavaScript
arrays. 

In particular, it is possible to crash the browser when performing
various operations on Array objects with 99999999999999999999999 or
0x23000000 elements. 

The crash is due to a segmentation fault and may be indicative of an
exploitable memory corruption vulnerability, possibly resulting in
arbitrary code execution. 

Solution : Upgrade to version 7.50 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 50))
    security_hole(port:get_kb_item("SMB/transport"), data:report);
}
