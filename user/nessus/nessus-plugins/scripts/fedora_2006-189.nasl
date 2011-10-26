#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21123);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1061");
 
 name["english"] = "Fedora Core 5 2006-189: curl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-189 (curl).

cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and
Dict servers, using any of the supported protocols. cURL is designed
to work without user interaction or any kind of interactivity. cURL
offers many useful capabilities, like proxy support, user
authentication, FTP upload, HTTP post, and file transfer resume.

Update Information:

This curl update fixes security vulnerability CVE-2006-1061 -
curl can overflow a heap-based memory buffer if very long
TFTP URL with valid host name is passed to curl.
This update fixes instalation problems on multilib
architectures, too.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the curl package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"curl-7.15.1-3", release:"FC5") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.15.1-3", release:"FC5") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"curl-", release:"FC5") )
{
 set_kb_item(name:"CVE-2006-1061", value:TRUE);
}
