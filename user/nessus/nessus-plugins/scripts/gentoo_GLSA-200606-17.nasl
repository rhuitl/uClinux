# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21710);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-17");
 script_cve_id("CVE-2006-2754");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-17
(OpenLDAP: Buffer overflow)


    slurpd contains a buffer overflow when reading very long hostnames from
    the status file.
  
Impact

    By injecting an overly long hostname in the status file, an attacker
    could possibly cause the execution of arbitrary code with the
    permissions of the user running slurpd.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2754


Solution: 
    All openLDAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-nds/openldap-2.3.22"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-17] OpenLDAP: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenLDAP: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-nsd/openldap", unaffected: make_list("ge 2.3.22"), vulnerable: make_list("lt 2.3.22")
)) { security_warning(0); exit(0); }
