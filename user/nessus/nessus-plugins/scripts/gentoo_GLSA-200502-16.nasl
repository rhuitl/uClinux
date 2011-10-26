# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16453);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-16");
 script_cve_id("CVE-2005-0085");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-16
(ht://Dig: Cross-site scripting vulnerability)


    Michael Krax discovered that ht://Dig fails to validate the
    \'config\' parameter before displaying an error message containing the
    parameter. This flaw could allow an attacker to conduct cross-site
    scripting attacks.
  
Impact

    By sending a carefully crafted message, an attacker can inject and
    execute script code in the victim\'s browser window. This allows to
    modify the behaviour of ht://Dig, and/or leak session information such
    as cookies to the attacker.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0085
    http://securitytracker.com/alerts/2005/Feb/1013078.html


Solution: 
    All ht://Dig users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-misc/htdig-3.1.6-r7"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-16] ht://Dig: Cross-site scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ht://Dig: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-misc/htdig", unaffected: make_list("ge 3.1.6-r7"), vulnerable: make_list("lt 3.1.6-r7")
)) { security_warning(0); exit(0); }
