# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16458);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-17
(Opera: Multiple vulnerabilities)


    Opera contains several vulnerabilities:
    fails to properly validate Content-Type and filename.
    fails to properly validate date: URIs.
    uses kfmclient exec as the Default Application to handle downloaded
    files when integrated with KDE.
    fails to properly control frames.
    uses Sun Java packages insecurely.
    searches an insecure path for plugins.
  
Impact

    An attacker could exploit these vulnerabilities to:
    execute arbitrary code.
    load a malicious frame in the context of another browser
    session.
    leak information.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.opera.com/linux/changelogs/754u1/
    http://www.opera.com/linux/changelogs/754u2/


Solution: 
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/opera-7.54-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-17] Opera: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/opera", unaffected: make_list("ge 7.54-r3"), vulnerable: make_list("lt 7.54-r3")
)) { security_warning(0); exit(0); }
