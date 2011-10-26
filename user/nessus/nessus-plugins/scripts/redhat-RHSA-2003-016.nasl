#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12352);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0435");

 name["english"] = "RHSA-2003-016: fileutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated fileutils packages are available which fix a race condition in
  recursive remove and move commands.

  The fileutils package includes a number of GNU versions of common and
  popular file management utilities.

  A race condition in recursive use of rm and mv commands in fileutils 4.1
  and earlier could allow local users to delete files and directories as the
  user running fileutils if the user has write access to part of the tree
  being moved or deleted.

  In addition, a bug in the way that the chown command parses --from options
  has also been fixed in these packages, bringing the command into Linux
  Standard Base (LSB) compliance.

  Users of Red Hat Linux Advanced Server should install the upgraded
  fileutils packages which contain patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-016.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fileutils packages";
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
if ( rpm_check( reference:"fileutils-4.1-10.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"fileutils-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0435", value:TRUE);
}

set_kb_item(name:"RHSA-2003-016", value:TRUE);
