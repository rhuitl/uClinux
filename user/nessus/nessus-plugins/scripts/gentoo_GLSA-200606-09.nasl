# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21702);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-09");
 script_cve_id("CVE-2006-2447");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-09
(SpamAssassin: Execution of arbitrary code)


    When spamd is run with both the "--vpopmail" (-v) and
    "--paranoid" (-P) options, it is vulnerable to an unspecified issue.
  
Impact

    With certain configuration options, a local or even remote
    attacker could execute arbitrary code with the rights of the user
    running spamd, which is root by default, by sending a crafted message
    to the spamd daemon. Furthermore, the attack can be remotely
    performed if the "--allowed-ips" (-A) option is present and specifies
    non-local adresses. Note that Gentoo Linux is not vulnerable in the
    default configuration.
  
Workaround

    Don\'t use both the "--paranoid" (-P) and the "--vpopmail" (-v)
    options.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2447


Solution: 
    All SpamAssassin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-filter/spamassassin-3.1.3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-09] SpamAssassin: Execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SpamAssassin: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-filter/spamassassin", unaffected: make_list("ge 3.1.3"), vulnerable: make_list("lt 3.1.3")
)) { security_hole(0); exit(0); }
