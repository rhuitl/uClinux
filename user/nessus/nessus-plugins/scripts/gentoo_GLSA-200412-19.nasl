# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16006);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-19");
 script_cve_id("CVE-2004-1147", "CVE-2004-1148");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-19
(phpMyAdmin: Multiple vulnerabilities)


    Nicolas Gregoire (exaprobe.com) has discovered two vulnerabilities
    that exist only on a webserver where PHP safe_mode is off. These
    vulnerabilities could lead to command execution or file disclosure.
  
Impact

    On a system where external MIME-based transformations are enabled,
    an attacker can insert offensive values in MySQL, which would start a
    shell when the data is browsed. On a system where the UploadDir is
    enabled, read_dump.php could use the unsanitized sql_localfile variable
    to disclose a file.
  
Workaround

    You can temporarily enable PHP safe_mode or disable external
    MIME-based transformation AND disable the UploadDir. But instead, we
    strongly advise to update your version to 2.6.1_rc1.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1147
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1148
    http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-4
    http://www.exaprobe.com/labs/advisories/esa-2004-1213.html


Solution: 
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.6.1_rc1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-19] phpMyAdmin: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.6.1_rc1"), vulnerable: make_list("lt 2.6.1_rc1")
)) { security_hole(0); exit(0); }
