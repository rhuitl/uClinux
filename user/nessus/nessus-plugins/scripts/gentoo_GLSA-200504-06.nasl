# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17993);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200504-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-06
(sharutils: Insecure temporary file creation)


    Joey Hess has discovered that the program unshar, which is a part
    of sharutils, creates temporary files in a world-writable directory
    with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When unshar is executed, this would result in the file being
    overwritten with the rights of the user running the utility, which
    could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.ubuntulinux.org/support/documentation/usn/usn-104-1


Solution: 
    All sharutils users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/sharutils-4.2.1-r11"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-06] sharutils: Insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sharutils: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/sharutils", unaffected: make_list("ge 4.2.1-r11"), vulnerable: make_list("lt 4.2.1-r11")
)) { security_warning(0); exit(0); }
