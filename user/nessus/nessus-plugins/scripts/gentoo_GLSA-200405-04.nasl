# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14490);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-04");
 script_cve_id("CVE-2004-0179");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-04
(OpenOffice.org vulnerability when using DAV servers)


    OpenOffice.org includes code from the Neon library in functions related to
    publication on WebDAV servers. This library is vulnerable to several format
    string attacks.
  
Impact

    If you use the WebDAV publication and connect to a malicious WebDAV server,
    this server can exploit these vulnerabilities to execute arbitrary code
    with the rights of the user running OpenOffice.org.
  
Workaround

    As a workaround, you should not use the WebDAV publication facilities.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0179
    http://www.gentoo.org/security/en/glsa/glsa-200405-01.xml


Solution: 
    There is no Ximian OpenOffice.org binary version including the fix yet. All
    users of the openoffice-ximian-bin package making use of the WebDAV
    openoffice-ximian source-based package.
    openoffice users on the x86 architecture should:
    # emerge sync
    # emerge -pv ">=app-office/openoffice-1.1.1-r1"
    # emerge ">=app-office/openoffice-1.1.1-r1"
    openoffice users on the sparc architecture should:
    # emerge sync
    # emerge -pv ">=app-office/openoffice-1.1.0-r3"
    # emerge ">=app-office/openoffice-1.1.0-r3"
    openoffice users on the ppc architecture should:
    # emerge sync
    # emerge -pv ">=app-office/openoffice-1.0.3-r1"
    # emerge ">=app-office/openoffice-1.0.3-r1"
    openoffice-ximian users should:
    # emerge sync
    # emerge -pv ">=app-office/openoffice-ximian-1.1.51-r1"
    # emerge ">=app-office/openoffice-ximian-1.1.51-r1"
    openoffice-bin users should:
    # emerge sync
    # emerge -pv ">=app-office/openoffice-bin-1.1.2"
    # emerge ">=app-office/openoffice-bin-1.1.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-04] OpenOffice.org vulnerability when using DAV servers");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org vulnerability when using DAV servers');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-office/openoffice", arch: "sparc", unaffected: make_list("ge 1.1.0-r4"), vulnerable: make_list("le 1.1.0-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice-ximian-bin", unaffected: make_list(), vulnerable: make_list("le 1.1.52")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice-ximian", unaffected: make_list("ge 1.1.51-r1"), vulnerable: make_list("le 1.1.51")
)) { security_hole(0); exit(0); }
