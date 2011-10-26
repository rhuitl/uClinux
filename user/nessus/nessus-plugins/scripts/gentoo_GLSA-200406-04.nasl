# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14515);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200406-04");
 script_cve_id("CVE-2004-0412");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-04
(Mailman: Member password disclosure vulnerability)


    Mailman contains an unspecified vulnerability in the handling of request
    emails.
  
Impact

    By sending a carefully crafted email request to the mailman server an
    attacker could obtain member passwords.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://mail.python.org/pipermail/mailman-announce/2004-May/000072.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0412


Solution: 
    All users of Mailman should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-mail/mailman-2.1.5"
    # emerge ">=net-mail/mailman-2.1.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-04] Mailman: Member password disclosure vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mailman: Member password disclosure vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/mailman", unaffected: make_list("ge 2.1.5"), vulnerable: make_list("lt 2.1.5")
)) { security_warning(0); exit(0); }
