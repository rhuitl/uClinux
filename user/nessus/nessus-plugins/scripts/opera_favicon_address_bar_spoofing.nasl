#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: GreyMagic <http://www.greymagic.com/> and Tom Gilder
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14245);
 script_cve_id("CVE-2004-0537");
 script_bugtraq_id(10452);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"6590");
 }
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Opera web browser address bar spoofing weakness (2)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host contains a web browser that is vulnerable to 
address bar spoofing attacks.

Description :

The version of Opera is vulnerable to a security weakness that may
permit malicious web pages to spoof address bar information.  It is
reported that the 'favicon' feature can be used to spoof the domain of
a malicious web page.  An attacker can create an icon that includes
the text of the desired site and is similar to the way Opera displays
information in the address bar.  The attacker can then obfuscate the
real address with spaces. 

This issue can be used to spoof information in the address bar, page
bar and page/window cycler. 

See also : 

http://www.greymagic.com/security/advisories/gm007-op/
http://www.opera.com/windows/changelogs/751/

Solution : 

Install to Opera 7.51 or newer.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:N)";



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
  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 51)) 
    security_note(get_kb_item("SMB/transport"));
}
