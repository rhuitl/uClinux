# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19366);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200508-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-03
(nbSMTP: Format string vulnerability)


    Niels Heinen discovered a format string vulnerability.
  
Impact

    An attacker can setup a malicious SMTP server and exploit this
    vulnerability to execute arbitrary code with the permissions of the
    user running nbSMTP.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://nbsmtp.ferdyx.org/


Solution: 
    All nbSMTP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/nbsmtp-1.0"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-03] nbSMTP: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'nbSMTP: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-mta/nbsmtp", unaffected: make_list("ge 1.00"), vulnerable: make_list("lt 1.00")
)) { security_warning(0); exit(0); }
