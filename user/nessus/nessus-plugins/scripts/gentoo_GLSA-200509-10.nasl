# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19742);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200509-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-10
(Mailutils: Format string vulnerability in imap4d)


    The imap4d server contains a format string bug in the handling of
    IMAP SEARCH requests.
  
Impact

    An authenticated IMAP user could exploit the format string error
    in imap4d to execute arbitrary code as the imap4d user, which is
    usually root.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.idefense.com/application/poi/display?id=303&type=vulnerabilities


Solution: 
    All GNU Mailutils users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/mailutils-0.6-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-10] Mailutils: Format string vulnerability in imap4d");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mailutils: Format string vulnerability in imap4d');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/mailutils", unaffected: make_list("ge 0.6-r2"), vulnerable: make_list("lt 0.6-r2")
)) { security_hole(0); exit(0); }
