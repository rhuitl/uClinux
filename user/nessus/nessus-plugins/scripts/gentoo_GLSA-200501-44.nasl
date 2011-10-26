# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-44.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16435);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-44");
 script_cve_id("CVE-2005-0013", "CVE-2005-0014");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-44
(ncpfs: Multiple vulnerabilities)


    Erik Sjolund discovered two vulnerabilities in the programs
    bundled with ncpfs: there is a potentially exploitable buffer overflow
    in ncplogin (CVE-2005-0014), and due to a flaw in nwclient.c, utilities
    using the NetWare client functions insecurely access files with
    elevated privileges (CVE-2005-0013).
  
Impact

    The buffer overflow might allow a malicious remote NetWare server
    to execute arbitrary code on the NetWare client. Furthermore, a local
    attacker may be able to create links and access files with elevated
    privileges using SUID ncpfs utilities.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0013
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0014
    ftp://platan.vc.cvut.cz/pub/linux/ncpfs/Changes-2.2.6


Solution: 
    All ncpfs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/ncpfs-2.2.6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-44] ncpfs: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ncpfs: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/ncpfs", unaffected: make_list("ge 2.2.6"), vulnerable: make_list("lt 2.2.6")
)) { security_warning(0); exit(0); }
