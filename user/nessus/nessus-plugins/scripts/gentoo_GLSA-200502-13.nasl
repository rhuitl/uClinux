# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16450);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-13");
 script_cve_id("CVE-2005-0155", "CVE-2005-0156");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-13
(Perl: Vulnerabilities in perl-suid wrapper)


    perl-suid scripts honor the PERLIO_DEBUG environment variable and
    write to that file with elevated privileges (CVE-2005-0155).
    Furthermore, calling a perl-suid script with a very long path while
    PERLIO_DEBUG is set could trigger a buffer overflow (CVE-2005-0156).
  
Impact

    A local attacker could set the PERLIO_DEBUG environment variable
    and call existing perl-suid scripts, resulting in file overwriting and
    potentially the execution of arbitrary code with root privileges.
  
Workaround

    You are not vulnerable if you do not have the perlsuid USE flag
    set or do not use perl-suid scripts.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0155
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0156


Solution: 
    All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-13] Perl: Vulnerabilities in perl-suid wrapper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Perl: Vulnerabilities in perl-suid wrapper');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/perl", unaffected: make_list("ge 5.8.6-r3", "rge 5.8.5-r4", "rge 5.8.4-r3", "rge 5.8.2-r3"), vulnerable: make_list("lt 5.8.6-r3")
)) { security_hole(0); exit(0); }
