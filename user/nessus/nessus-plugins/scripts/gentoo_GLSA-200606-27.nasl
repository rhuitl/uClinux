# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21773);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-27");
 script_cve_id("CVE-2006-3242");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-27
(Mutt: Buffer overflow)


    TAKAHASHI Tamotsu has discovered that Mutt contains a boundary error in
    the "browse_get_namespace()" function in browse.c, which can be
    triggered when receiving an overly long namespace from an IMAP server.
  
Impact

    A malicious IMAP server can send an overly long namespace to Mutt in
    order to crash the application, and possibly execute arbitrary code
    with the permissions of the user running Mutt.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3242


Solution: 
    All Mutt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mutt-1.5.11-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-27] Mutt: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mutt: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/mutt", unaffected: make_list("ge 1.5.11-r2"), vulnerable: make_list("lt 1.5.11-r2")
)) { security_warning(0); exit(0); }
