# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21712);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-19");
 script_cve_id("CVE-2006-1173");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-19
(Sendmail: Denial of Service)


    Frank Sheiness discovered that the mime8to7() function can recurse
    endlessly during the decoding of multipart MIME messages until the
    stack of the process is filled and the process crashes.
  
Impact

    By sending specially crafted multipart MIME messages, a remote
    attacker can cause a subprocess forked by Sendmail to crash. If
    Sendmail is not set to use a randomized queue processing, the attack
    will effectively halt the delivery of queued mails as well as the
    malformed one, incoming mail delivered interactively is not affected.
    Additionally, on systems where core dumps with an individual naming
    scheme (like "core.pid") are enabled, a filesystem may fill up with
    core dumps. Core dumps are disabled by default in Gentoo.
  
Workaround

    The Sendmail 8.13.7 release information offers some workarounds, please
    see the Reference below. Note that the issue has actually been fixed in
    the 8.13.6-r1 ebuild.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1173
    http://www.sendmail.org/releases/8.13.7.html


Solution: 
    All Sendmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/sendmail-8.13.6-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-19] Sendmail: Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sendmail: Denial of Service');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-mta/sendmail", unaffected: make_list("ge 8.13.6-r1"), vulnerable: make_list("lt 8.13.6-r1")
)) { security_warning(0); exit(0); }
