# This script was automatically generated from the dsa-043
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'This advisory covers several vulnerabilities in Zope that
have been addressed.


Hotfix 08_09_2000 "Zope security alert and hotfix product"

    The issue involves the fact that the getRoles method of user objects
    contained in the default UserFolder implementation returns a mutable
    Python type.  Because the mutable object is still associated with
    the persistent User object, users with the ability to edit DTML
    could arrange to give themselves extra roles for the duration of a
    single request by mutating the roles list as a part of the request
    processing.

Hotfix 2000-10-02 "ZPublisher security update"

    It is sometimes possible to access, through a URL only, objects
    protected by a role which the user has in some context, but not in
    the context of the accessed object.

Hotfix 2000-10-11 "ObjectManager subscripting"

    The issue involves the fact that the \'subscript notation\' that can
    be used to access items of ObjectManagers (Folders) did not
    correctly restrict return values to only actual sub items.  This
    made it possible to access names that should be private from DTML
    (objects with names beginning with the underscore \'_\' character).
    This could allow DTML authors to see private implementation data
    structures and in certain cases possibly call methods that they
    shouldn\'t have access to from DTML.

Hotfix 2001-02-23 "Class attribute access"

    The issue is related to ZClasses in that a user with through-the-web
    scripting capabilities on a Zope site can view and assign class
    attributes to ZClasses, possibly allowing them to make inappropriate
    changes to ZClass instances.
    
    A second part fixes problems in the ObjectManager, PropertyManager,
    and PropertySheet classes related to mutability of method return
    values which could be perceived as a security problem.


These fixes are included in zope 2.1.6-7 for Debian 2.2 (potato). We recommend
you upgrade your zope package immediately.



Solution : http://www.debian.org/security/2001/dsa-043
Risk factor : High';

if (description) {
 script_id(14880);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "043");
 script_cve_id("CVE-2001-0568", "CVE-2001-0569");
 script_bugtraq_id(2458);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA043] DSA-043-1 zope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-043-1 zope");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zope', release: '2.2', reference: '2.1.6-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope is vulnerable in Debian 2.2.\nUpgrade to zope_2.1.6-7\n');
}
if (w) { security_hole(port: 0, data: desc); }
