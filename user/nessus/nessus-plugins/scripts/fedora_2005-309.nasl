#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19647);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0372");
 
 name["english"] = "Fedora Core 3 2005-309: gftp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-309 (gftp).

gFTP is a multi-threaded FTP client for the X Window System. gFTP
supports simultaneous downloads, resumption of interrupted file
transfers, file transfer queues to allow downloading of multiple
files, support for downloading entire directories/subdirectories, a
bookmarks menu to allow quick connection to FTP sites, caching of
remote directory listings, local and remote chmod, drag and drop, a
connection manager and much more.

Install gftp if you need a graphical FTP client.


* Fri Feb 18 2005 Warren Togami <wtogami redhat com> 2.0.18-0.FC3

- FC3 (including CVE-2005-0372)

* Thu Feb 10 2005 Warren Togami <wtogami redhat com> 2.0.18-1

- 2.0.18




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gftp package";
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
if ( rpm_check( reference:"gftp-2.0.18-0.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gftp-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0372", value:TRUE);
}
