# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-25.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16067);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-25");
 script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-25
(CUPS: Multiple vulnerabilities)


    CUPS makes use of vulnerable Xpdf code to handle PDF files
    (CVE-2004-1125). Furthermore, Ariel Berkman discovered a buffer
    overflow in the ParseCommand function in hpgl-input.c in the hpgltops
    program (CVE-2004-1267). Finally, Bartlomiej Sieka discovered several
    problems in the lppasswd program: it ignores some write errors
    (CVE-2004-1268), it can leave the passwd.new file in place
    (CVE-2004-1269) and it does not verify that passwd.new file is
    different from STDERR (CVE-2004-1270).
  
Impact

    The Xpdf and hpgltops vulnerabilities may be exploited by a remote
    attacker to execute arbitrary code by sending specific print jobs to a
    CUPS spooler. The lppasswd vulnerabilities may be exploited by a local
    attacker to write data to the CUPS password file or deny further
    password modifications.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1125
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1267
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1268
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1269
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1270
    http://tigger.uic.edu/~jlongs2/holes/cups.txt
    http://tigger.uic.edu/~jlongs2/holes/cups2.txt


Solution: 
    All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.1.23"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-25] CUPS: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.1.23"), vulnerable: make_list("lt 1.1.23")
)) { security_hole(0); exit(0); }
