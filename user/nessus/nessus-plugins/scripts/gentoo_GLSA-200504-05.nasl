# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17992);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-05");
 script_cve_id("CVE-2005-0967", "CVE-2005-0966", "CVE-2005-0965");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-05
(Gaim: Denial of Service issues)


    Multiple vulnerabilities have been addressed in the latest release of
    Gaim:
    A buffer overread in the gaim_markup_strip_html() function,
    which is used when logging conversations (CVE-2005-0965).
    Markup tags are improperly escaped using Gaim\'s IRC plugin
    (CVE-2005-0966).
    Sending a specially crafted file transfer request to a Gaim Jabber
    user can trigger a crash (CVE-2005-0967).
  
Impact

    An attacker could possibly cause a Denial of Service by exploiting any
    of these vulnerabilities.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0967
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0966
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0965
    http://gaim.sourceforge.net/security/


Solution: 
    All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gaim-1.2.1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-05] Gaim: Denial of Service issues");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Denial of Service issues');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.2.1"), vulnerable: make_list("lt 1.2.1")
)) { security_warning(0); exit(0); }
