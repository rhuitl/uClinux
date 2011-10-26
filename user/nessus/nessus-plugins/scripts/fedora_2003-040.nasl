#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13668);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2003-040: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-040 (ethereal).

operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.

Update Information:

 Serious issues have been discovered in the following protocol dissectors:

    * Selecting 'Match->Selected' or 'Prepare->Selected' for a
malformed SMB packet could cause a segmentation fault.
    * It is possible for the Q.931 dissector to dereference a null
pointer when reading a malformed packet.

Impact:

Both vulnerabilities will make the Ethereal application crash. The Q.931
vulnerability also affects Tethereal. It is not known if either
vulnerability can be used to make Ethereal or Tethereal run arbitrary code.

Resolution:

Upgrade to 0.10.0.

If you are running a version prior to 0.10.0 and you cannot upgrade, you
can disable the SMB and Q.931 protocol dissectors by selecting
Edit->Protocols... and deselecting them from the list.


Solution : http://www.fedoranews.org/updates/FEDORA-2003-040.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.0a-0.1", prefix:"ethereal-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
