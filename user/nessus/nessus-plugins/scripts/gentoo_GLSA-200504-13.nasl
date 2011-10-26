# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18060);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-13");
 script_cve_id("CVE-2005-0941");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-13
(OpenOffice.Org: DOC document Heap Overflow)


    AD-LAB has discovered a heap overflow in the "StgCompObjStream::Load()"
    function when processing DOC documents.
  
Impact

    An attacker could design a malicious DOC document containing a
    specially crafted header which, when processed by OpenOffice.Org, would
    result in the execution of arbitrary code with the rights of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.openoffice.org/issues/show_bug.cgi?id=46388
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0941


Solution: 
    All OpenOffice.Org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-1.1.4-r1"
    All OpenOffice.Org binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-bin-1.1.4-r1"
    All OpenOffice.Org Ximian users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-office/openoffice-ximian
    Note to PPC users: There is no stable OpenOffice.Org fixed version for
    the PPC architecture. Affected users should switch to the latest
    OpenOffice.Org Ximian version.
    Note to SPARC users: There is no stable OpenOffice.Org fixed version
    for the SPARC architecture. Affected users should switch to the latest
    OpenOffice.Org Ximian version.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-13] OpenOffice.Org: DOC document Heap Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.Org: DOC document Heap Overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-office/openoffice-ximian", unaffected: make_list("ge 1.3.9-r1", "rge 1.3.6-r1", "rge 1.3.7-r1"), vulnerable: make_list("lt 1.3.9-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 1.1.4-r1"), vulnerable: make_list("lt 1.1.4-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 1.1.4-r1"), vulnerable: make_list("lt 1.1.4-r1")
)) { security_warning(0); exit(0); }
