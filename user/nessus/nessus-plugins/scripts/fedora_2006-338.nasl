#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21249);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1057");
 
 name["english"] = "Fedora Core 5 2006-338: gdm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-338 (gdm).

Gdm (the GNOME Display Manager) is a highly configurable
reimplementation of xdm, the X Display Manager. Gdm allows you to log
into your system with the X Window System running and supports running
several different X sessions on your local machine at the same time.

Update Information:

(Notes taken from upstream release mail)

- The sockets connection between the slaves and the GDM
daemon is now
better managed to better ensure that sockets are never left
open.
(Brian Cameron)

- Corrected bug that causes a core dump when you click on
gdmgreeter
fields that have an id.  (Brian Cameron)

- Add new GdmXserverTimeout configuration setting so that
the length of
time GDM waits for the Xserver to start can be tuned, so
GDM better
works with Xservers that require more than 10 seconds to start.
(Emilie)

- The happygnome and happygnome-list gdmgreeter themes now
use the
official logo.  (Brian Cameron)

- Now GDM configure supports --with-sysconfsubdir so that GDM's
configuration directory can be configured to not have
'/gdm' appended
to the end.

- Fix for ensuring .ICEauthority file has proper
ownership/permissions.
Addresses CVE-2006-1057.  (Hans Petter Jansson)

- Fix 'Show Actions Menu' section in gdmsetup so it appears
when both
'Plain' and 'Themed' style is chosen.  (Brian Cameron, Dennis
Cranston)

- Now use LINGUAS procedure for defining languages.
(Michiel Sikkes)

- Now Xsession script uses '$@' instead of '$1' so it is
possible to
pass arguments with the command to run.  (Brian Cameron)

- Add Trusted Solraris support.  (Niall Power)

- One line fix to Solaris auditing logic that fixes a bug
causing
authentication to fail when auditing is turned on.  (Brian
Cameron)

- Fixes to compile with C99 and fixes to compile under NetBSD.
Remove EXPANDED_* variables from the configure.  (Julio M.
Merino
Vidal)

- Translation updates (ÃÂ½ygimantas BeruÃÂka,
BenoÃÂ®t
Dejean, Laurent Dhima, Maxim Dziumanenko, Alessio
Frusciante, Rhys
Jones, Raphael Higino, Theppitak Karoonboonyanan, Gabor Kelmen,
Priit Laes, Jordi Mallach, Kjartan Maraas, Daniel Nylander,
Kostas
Papdimas, Guilherme de S. Pastore, Ankit Patel, Ignacio Casal
Quinteiro, Hendrik Richter, Jens Seidel, Francisco Javier
F. Serrador,
Alexander Shopov, Clytie Siddall, Ilkka Tuohela, Vincent
van Adrighem,
Tommi Vainikaninen)


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdm package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gdm-2.14.1-1.fc5.2", release:"FC5") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gdm-", release:"FC5") )
{
 set_kb_item(name:"CVE-2006-1057", value:TRUE);
}
