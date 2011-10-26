# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20198);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-11");
 script_cve_id("CVE-2005-3524");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-11
(linux-ftpd-ssl: Remote buffer overflow)


    A buffer overflow vulnerability has been found in the
    linux-ftpd-ssl package. A command that generates an excessively long
    response from the server may overrun a stack buffer.
  
Impact

    An attacker that has permission to create directories that are
    accessible via the FTP server could exploit this vulnerability.
    Successful exploitation would execute arbitrary code on the local
    machine with root privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3524


Solution: 
    All ftpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/ftpd-0.17-r3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-11] linux-ftpd-ssl: Remote buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'linux-ftpd-ssl: Remote buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-ftp/ftpd", unaffected: make_list("ge 0.17-r3"), vulnerable: make_list("lt 0.17-r3")
)) { security_hole(0); exit(0); }
