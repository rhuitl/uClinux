# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20357);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-16");
 script_cve_id("CVE-2005-3964");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-16
(OpenMotif, AMD64 x86 emulation X libraries: Buffer overflows in libUil library)


    xfocus discovered two potential buffer overflows in the libUil
    library, in the diag_issue_diagnostic and open_source_file functions.
  
Impact

    Remotely-accessible or SUID applications making use of the
    affected functions might be exploited to execute arbitrary code with
    the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3964
    http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0047.html


Solution: 
    All OpenMotif users should upgrade to an unaffected version:
    # emerge --sync
    # emerge --ask --oneshot --verbose x11-libs/openmotif
    All AMD64 x86 emulation X libraries users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-emulation/emul-linux-x86-xlibs
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-16] OpenMotif, AMD64 x86 emulation X libraries: Buffer overflows in libUil library");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenMotif, AMD64 x86 emulation X libraries: Buffer overflows in libUil library');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-emulation/emul-linux-x86-xlibs", arch: "AMD64", unaffected: make_list("ge 2.2.1"), vulnerable: make_list("lt 2.2.1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-libs/openmotif", unaffected: make_list("ge 2.2.3-r8", "rge 2.1.30-r13"), vulnerable: make_list("lt 2.2.3-r8")
)) { security_warning(0); exit(0); }
