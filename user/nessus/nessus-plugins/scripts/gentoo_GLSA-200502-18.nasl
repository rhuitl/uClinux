# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16459);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-18
(VMware Workstation: Untrusted library search path)


    Tavis Ormandy of the Gentoo Linux Security Audit Team has
    discovered that VMware Workstation searches for gdk-pixbuf loadable
    modules in an untrusted, world-writable directory.
  
Impact

    A local attacker could create a malicious shared object that would
    be loaded by VMware, resulting in the execution of arbitrary code with
    the privileges of the user running VMware.
  
Workaround

    The system administrator may create the file /tmp/rrdharan to
    prevent malicious users from creating a directory at that location:
    # touch /tmp/rrdharan
  

Solution: 
    All VMware Workstation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/vmware-workstation-4.5.2.8848-r5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-18] VMware Workstation: Untrusted library search path");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VMware Workstation: Untrusted library search path');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-emulation/vmware-workstation", unaffected: make_list("ge 4.5.2.8848-r5"), vulnerable: make_list("lt 4.5.2.8848-r5")
)) { security_warning(0); exit(0); }
