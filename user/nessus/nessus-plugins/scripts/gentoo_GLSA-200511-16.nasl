# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20244);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-16");
 script_cve_id("CVE-2005-3349", "CVE-2005-3355");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-16
(GNUMP3d: Directory traversal and insecure temporary file creation)


    Ludwig Nussel from SUSE Linux has identified two vulnerabilities
    in GNUMP3d. GNUMP3d fails to properly check for the existence of
    /tmp/index.lok before writing to the file, allowing for local
    unauthorized access to files owned by the user running GNUMP3d. GNUMP3d
    also fails to properly validate the "theme" GET variable from CGI
    input, allowing for unauthorized file inclusion.
  
Impact

    An attacker could overwrite files owned by the user running
    GNUMP3d by symlinking /tmp/index.lok to the file targeted for
    overwrite. An attacker could also include arbitrary files by traversing
    up the directory tree (at most two times, i.e. "../..") with the
    "theme" GET variable.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3349
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3355
    http://www.gnu.org/software/gnump3d/ChangeLog


Solution: 
    All GNUMP3d users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/gnump3d-2.9.7-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-16] GNUMP3d: Directory traversal and insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNUMP3d: Directory traversal and insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/gnump3d", unaffected: make_list("ge 2.9.7-r1"), vulnerable: make_list("lt 2.9.7-r1")
)) { security_warning(0); exit(0); }
