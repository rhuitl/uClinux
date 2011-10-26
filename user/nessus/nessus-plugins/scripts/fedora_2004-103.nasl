#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13686);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2004-103: neon";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-103 (neon).

neon is an HTTP and WebDAV client library, with a C interface;
providing a high-level interface to HTTP and WebDAV methods along
with a low-level interface for HTTP request handling.  neon
supports persistent connections, proxy servers, basic, digest and
Kerberos authentication, and has complete SSL support.

Update Information:

Multiple format string vulnerabilities in neon 0.24.4 and earlier
allow remote malicious WebDAV servers to execute arbitrary code.

Updated packages were made available in April 2004 however the original
update notification email did not make it to fedora-announce-list at
that time.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-103.shtml
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
if ( rpm_check( reference:"neon-0.24.5-1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"neon-devel-0.24.5-1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"neon-debuginfo-0.24.5-1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
