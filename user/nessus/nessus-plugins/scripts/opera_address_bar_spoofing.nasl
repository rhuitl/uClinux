#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: Jakob Balle
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14244);
 script_cve_id("CVE-2004-2260");
 script_bugtraq_id(10337);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"6108");
 }
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Opera web browser address bar spoofing weakness";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

This version of Opera is vulnerable to a security weakness 
that may permit malicious web pages to spoof address bar information.

This is reportedly possible through malicious use of the 
JavaScript 'unOnload' event handler when the browser 
is redirected to another page.

This issue could be exploited to spoof the domain of a malicious web page, 
potentially causing the victim user to trust the spoofed domain.

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
We have determined that you are running Opera v." + v + ". This version
is vulnerable to a security weakness that may permit malicious web pages 
to spoof address bar information. 

This is reportedly possible through malicious use of the 
JavaScript 'unOnload' event handler when the browser 
is redirected to another page. 

This issue could be exploited to spoof the domain of a malicious web page, 
potentially causing the victim user to trust the spoofed domain.

Solution : Upgrade to version 7.50 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 50))security_hole(port:get_kb_item("SMB/transport"), data:report);
}
