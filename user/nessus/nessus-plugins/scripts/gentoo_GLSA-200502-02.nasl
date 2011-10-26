# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16439);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-02
(UW IMAP: CRAM-MD5 authentication bypass)


    A logic bug in the code handling CRAM-MD5 authentication
    incorrectly specifies the condition for successful authentication.
  
Impact

    An attacker could exploit this vulnerability to authenticate as
    any mail user on a server with CRAM-MD5 authentication enabled.
  
Workaround

    Disable CRAM-MD5 authentication.
  
References:
    http://www.kb.cert.org/vuls/id/702777


Solution: 
    All UW IMAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/uw-imap-2004b"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-02] UW IMAP: CRAM-MD5 authentication bypass");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'UW IMAP: CRAM-MD5 authentication bypass');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/uw-imap", unaffected: make_list("ge 2004b"), vulnerable: make_list("le 2004a")
)) { security_warning(0); exit(0); }
