#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20029);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-3185");
 
 name["english"] = "Fedora Core 3 2005-996: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-996 (wget).

GNU Wget is a file retrieval utility which can use either the HTTP or
FTP protocols. Wget features include the ability to work in the
background while you are logged out, recursive retrieval of
directories, file name wildcard matching, remote file timestamp
storage and comparison, use of Rest with FTP servers and Range with
HTTP servers to retrieve files over slow or unstable connections,
support for Proxy servers, and configurability.

Update Information:

This package fixes a buffer overflow bug in the NTLM
authentication code of wget (CVE-2005-3185).


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget package";
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
if ( rpm_check( reference:"wget-1.10.2-0.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"wget-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-3185", value:TRUE);
}
