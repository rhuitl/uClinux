#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12334);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1344");

 name["english"] = "RHSA-2002-256: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  The wget packages shipped with Red Hat Linux Advanced Server 2.1 contain a
  security bug which, under certain circumstances, can cause local files to
  be written outside the download directory.

  [Updated 09 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Versions of wget prior to 1.8.2-4 contain a bug that permits a malicious
  FTP server to create or overwrite files anywhere on the local file system.

  FTP clients must check to see if an FTP server\'s response to the NLST
  command includes any directory information along with the list of filenames
  required by the FTP protocol (RFC 959, section 4.1.3).

  If the FTP client fails to do so, a malicious FTP server can send filenames
  beginning with \'/\' or containing \'/../\' which can be used to direct a
  vulnerable FTP client to write files (such as .forward, .rhosts, .shost,
  etc.) that can then be used for later attacks against the client machine.

  All users of wget should upgrade to the errata packages which are not
  vulnerable to this issue.

  Thanks to Steven M. Christey for his work in discovering this issue
  in current FTP clients and for providing a patched FTP server to verify
  the new packages.




Solution : http://rhn.redhat.com/errata/RHSA-2002-256.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"wget-1.8.2-4.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"wget-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1344", value:TRUE);
}

set_kb_item(name:"RHSA-2002-256", value:TRUE);
