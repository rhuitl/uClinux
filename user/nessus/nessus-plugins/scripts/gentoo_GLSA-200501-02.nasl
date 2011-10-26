# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16393);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-02");
 script_cve_id("CVE-2004-1170");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-02
(a2ps: Multiple vulnerabilities)


    Javier Fernandez-Sanguino Pena discovered that the a2ps package
    contains two scripts that create insecure temporary files (fixps and
    psmandup). Furthermore, we fixed in a previous revision a vulnerability
    in a2ps filename handling (CVE-2004-1170).
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When
    fixps or psmandup is executed, this would result in the file being
    overwritten with the rights of the user running the utility. By
    enticing a user or script to run a2ps on a malicious filename, an
    attacker could execute arbitrary commands on the system with the rights
    of that user or script.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/13641/
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1170
    http://lists.netsys.com/pipermail/full-disclosure/2004-August/025678.html


Solution: 
    All a2ps users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/a2ps-4.13c-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-02] a2ps: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'a2ps: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/a2ps", unaffected: make_list("ge 4.13c-r2"), vulnerable: make_list("lt 4.13c-r2")
)) { security_warning(0); exit(0); }
