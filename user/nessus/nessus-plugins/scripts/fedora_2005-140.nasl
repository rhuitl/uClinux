#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16374);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0088");
 
 name["english"] = "Fedora Core 3 2005-140: mod_python";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-140 (mod_python).

Mod_python is a module that embeds the Python language interpreter
within
the server, allowing Apache handlers to be written in Python.

Mod_python brings together the versatility of Python and the power of
the Apache Web server for a considerable boost in flexibility and
performance over the traditional CGI approach.

Update Information:

Graham Dumpleton discovered a flaw affecting the publisher handler of
mod_python, used to make objects inside modules callable via URL.
A remote user could visit a carefully crafted URL that would gain
access to
objects that should not be visible, leading to an information leak.
The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned
the name CVE-2005-0088 to this issue.

This update includes a patch which fixes this issue.



Solution : http://www.fedoranews.org/blog/index.php?p=392
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_python package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mod_python-3.1.3-5.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_python-debuginfo-3.1.3-5.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mod_python-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0088", value:TRUE);
}
