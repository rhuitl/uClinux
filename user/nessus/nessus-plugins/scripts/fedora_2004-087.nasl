#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13681);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2004-087: libxml2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-087 (libxml2).

This library allows to manipulate XML files. It includes support
to read, modify and write XML and HTML files. There is DTDs support
this includes parsing and validation even with complex DtDs, either
at parse time or later once the document has been modified. The output
can be a simple SAX stream or and in-memory DOM like representations.
In this case one can use the built-in XPath and XPointer implementation
to select subnodes or ranges. A flexible Input/Output mechanism is
available, with existing HTTP and FTP modules and combined to an
URI library.

Update Information:

Updated libxml2 packages are available to fix an overflow when parsing
the URI for remote resources.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-087.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libxml2 package";
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
if ( rpm_check( reference:"libxml2-2.6.6-3", prefix:"libxml2-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
