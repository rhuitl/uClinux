# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22913);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-10");
 script_cve_id("CVE-2006-4182");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-10
(ClamAV: Multiple Vulnerabilities)


    Damian Put and an anonymous researcher reported a potential heap-based
    buffer overflow vulnerability in rebuildpe.c responsible for the
    rebuilding of an unpacked PE file, and a possible crash in chmunpack.c
    in the CHM unpacker.
  
Impact

    By sending a malicious attachment to a mail server running ClamAV, or
    providing a malicious file to ClamAV through any other method, a remote
    attacker could cause a Denial of Service and potentially the execution
    of arbitrary code with the permissions of the user running ClamAV.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://sourceforge.net/project/shownotes.php?release_id=455799
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4182


Solution: 
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.88.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-10] ClamAV: Multiple Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple Vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.88.5"), vulnerable: make_list("lt 0.88.5")
)) { security_hole(0); exit(0); }
