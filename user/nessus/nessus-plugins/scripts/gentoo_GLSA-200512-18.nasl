# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20371);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-18
(XnView: Privilege escalation)


    Krzysiek Pawlik of Gentoo Linux discovered that the XnView package
    for IA32 used the DT_RPATH field insecurely, causing the dynamic loader
    to search for shared libraries in potentially untrusted directories.
  
Impact

    A local attacker could create a malicious shared object that would
    be loaded and executed when a user attempted to use an XnView utility.
    This would allow a malicious user to effectively hijack XnView and
    execute arbitrary code with the privileges of the user running the
    program.
  
Workaround

    The system administrator may use the chrpath utility to remove the
    DT_RPATH field from the XnView utilities:
    # emerge app-admin/chrpath
    # chrpath --delete /opt/bin/nconvert /opt/bin/nview /opt/bin/xnview
  

Solution: 
    All XnView users on the x86 platform should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-misc/xnview-1.70-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-18] XnView: Privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XnView: Privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-misc/xnview", arch: "x86", unaffected: make_list("ge 1.70-r1"), vulnerable: make_list("lt 1.70-r1")
)) { security_warning(0); exit(0); }
