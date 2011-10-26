#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13704);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0398");
 
 name["english"] = "Fedora Core 1 2004-129: neon";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-129 (neon).

neon is an HTTP and WebDAV client library, with a C interface;
providing a high-level interface to HTTP and WebDAV methods along
with a low-level interface for HTTP request handling.  neon
supports persistent connections, proxy servers, basic, digest and
Kerberos authentication, and has complete SSL support.

Update Information:

Stefan Esser discovered a flaw in the neon library which allows a heap
buffer overflow in a date parsing routine. An attacker could create a
malicious WebDAV server in such a way as to allow arbitrary code
execution on the client should a user connect to it using a neon-based
application which uses the date parsing routines, such as cadaver.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0398 to this issue.  This update includes
packages with a patch for this issue.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-129.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the neon package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"neon-0.24.5-2.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"neon-devel-0.24.5-2.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"neon-debuginfo-0.24.5-2.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"neon-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0398", value:TRUE);
}
