# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17582);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-26");
 script_cve_id("CVE-2005-0667");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-26
(Sylpheed, Sylpheed-claws: Message reply overflow)


    Sylpheed and Sylpheed-claws fail to properly handle non-ASCII
    characters in email headers when composing reply messages.
  
Impact

    An attacker can send an email containing a malicious non-ASCII
    header which, when replied to, would cause the program to crash,
    potentially allowing the execution of arbitrary code with the
    privileges of the user running the software.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://sylpheed.good-day.net/#changes
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0667


Solution: 
    All Sylpheed users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/sylpheed-1.0.3"
    All Sylpheed-claws users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/sylpheed-claws-1.0.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-26] Sylpheed, Sylpheed-claws: Message reply overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sylpheed, Sylpheed-claws: Message reply overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/sylpheed", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("lt 1.0.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/sylpheed-claws", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("lt 1.0.3")
)) { security_warning(0); exit(0); }
