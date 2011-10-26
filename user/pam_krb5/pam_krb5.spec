Summary: A Pluggable Authentication Module for Kerberos 5.
Name: pam_krb5
Version: 2.3.7
Release: 1%{?dist}
Source0: pam_krb5-%{version}-1.tar.gz
License: BSD or LGPLv2+
Group: System Environment/Base
URL: https://fedorahosted.org/pam_krb5/
BuildPrereq: keyutils-libs-devel, krb5-devel, pam-devel
BuildRoot: %{_tmppath}/%{name}-root

%description 
This is pam_krb5, a pluggable authentication module that can be used with
Linux-PAM and Kerberos 5. This module supports password checking, ticket
creation, and optional TGT verification and conversion to Kerberos IV tickets.
The included pam_krb5afs module also gets AFS tokens if so configured.

%prep
%setup -q -n pam_krb5-%{version}-1

%build
CFLAGS="$RPM_OPT_FLAGS -fPIC"; export CFLAGS
%configure --libdir=/%{_lib} \
	--with-default-use-shmem=sshd --with-default-external=sshd
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
ln -s pam_krb5.so $RPM_BUILD_ROOT/%{_lib}/security/pam_krb5afs.so
rm -f $RPM_BUILD_ROOT/%{_lib}/security/*.la

# Make the paths jive to avoid conflicts on multilib systems.
sed -ri -e 's|/lib(64)?/|/\$LIB/|g' $RPM_BUILD_ROOT/%{_mandir}/man*/pam_krb5*.8*

%find_lang %{name}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT

%files -f %{name}.lang
%defattr(-,root,root)
%{_bindir}/*
/%{_lib}/security/pam_krb5.so
/%{_lib}/security/pam_krb5afs.so
/%{_lib}/security/pam_krb5
%{_mandir}/man1/*
%{_mandir}/man5/*
%{_mandir}/man8/*
%doc README* COPYING* ChangeLog NEWS

%changelog
* Fri Jun 26 2009 Nalin Dahyabhai <nalin@redhat.com> - 2.3.7-1
- when called to refresh credentials, store the new creds in the default
  ccache location if $KRB5CCNAME isn't set (#507984)

* Mon Jun 15 2009 Nalin Dahyabhai <nalin@redhat.com> - 2.3.6-1
- prefer keys for services matching the pattern host/*@clientrealm when
  validating (#450776)

* Fri Jun  5 2009 Nalin Dahyabhai <nalin@redhat.com> - 2.3.5-1
- when we get asked for the user's long-term key, use a plain Password:
  prompt value rather than the library-supplied one

* Tue May 26 2009 Nalin Dahyabhai <nalin@redhat.com>
- catch the case where we pass a NULL initial password into libkrb5 and
  it uses our callback to ask us for the password for the user using a
  principal name, and reject that (#502602)
- always prompt for a password unless we were told not to (#502602,
  CVE-2009-1384)

* Wed Mar  4 2009 Nalin Dahyabhai <nalin@redhat.com> - 2.3.4-1
- don't request password-changing credentials with the same options that we
  use when requesting ticket granting tickets, which might run afoul of KDC
  policies

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.3.3-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Fri Feb  6 2009 Nalin Dahyabhai <nalin@redhat.com> - 2.3.3-1
- clean up a couple of debug messages

* Fri Feb  6 2009 Nalin Dahyabhai <nalin@redhat.com>
- clean up a couple of unclosed pipes to nowhere

* Wed Oct  1 2008 Nalin Dahyabhai <nalin@redhat.com> - 2.3.2-1
- fix ccache permissions bypass when the "existing_ticket" option is used
  (CVE-2008-3825)

* Wed Aug 27 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 2.3.0-2
- fix license tag

* Wed Apr  9 2008 Nalin Dahyabhai <nalin@redhat.com> - 2.3.1-1
- don't bother trying to set up a temporary v4 ticket file during session open
  unless we obtained v4 creds somewhere

* Mon Mar 10 2008 Nalin Dahyabhai <nalin@redhat.com> - 2.3.0-1
- add a "null_afs" option
- add a "token_strategy" option

* Mon Mar 10 2008 Nalin Dahyabhai <nalin@redhat.com> - 2.2.23-1
- when we're changing passwords, force at least one attempt to authenticate
  using the KDC, even in the pathological case where there's no previously-
  entered password and we were told not to ask for one (#400611)

* Fri Feb  8 2008 Nalin Dahyabhai <nalin@redhat.com> - 2.2.22-1
- make sure we don't fall out of the calling process's PAG when we check
  the .k5login (fallout from #371761)
- make most boolean options controllable on a per-service basis

* Fri Nov  9 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.21-1
- make sure that we have tokens when checking the user's .k5login (#371761)

* Thu Nov  8 2007 Nalin Dahyabhai <nalin@redhat.com>
- set perms on the user's KEYRING: ccache so that the user can write to it
- suppress an error message if a KEYRING: ccache we're about to destroy has
  already been revoked

* Fri Oct 26 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.20-1
- move temporary ccaches which aren't used for serializing from FILE: type
  into MEMORY: type
- don't barf during credential refresh when $KRB5CCNAME isn't set

* Thu Oct 25 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.19-1
- log to AUTHPRIV facility by default
- add a "ccname_template" option, which can be set to "KEYRING:..." to switch
  to using the kernel keyring
- add a "preauth_options" option for setting generic preauth parameters
- allow "keytab" locations to be specified on a per-service basis, so that
  unprivileged apps which do password-checking and which have their own
  keytabs can use their own keys to validate the KDC's response

* Wed Aug 15 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.18-1
- fix permissions-related problems creating v4 ticket files

* Thu Aug  2 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.17-1
- correct the license: tag -- this module is dual-licensed (LGPL+ or BSD)
- fix a man page missing line
- tactfully suggest in the man page that if your app needs the "tokens"
  flag in order to work properly, it's broken

* Fri Jul 27 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.16-1
- update to 2.2.16, also avoiding use of the helper if we're creating a ticket
  file for our own use

* Mon Jul 23 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.15-2
- rebuild

* Mon Jul 23 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.15-1
- update to 2.2.15, adjusting the fix for #150056 so that it doesn't run
  afoul of SELinux policy by attempting to read a ccache which was created
  for use by the user via the helper
- build with --with-default-use-shmem=sshd --with-default-external=sshd, to
  get the expected behavior without requiring administrator intervention

* Thu Jul 19 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.14-2
- rebuild

* Fri Jul 13 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.14-1
- update to 2.2.14

* Thu Jul 12 2007 Nalin Dahyabhai <nalin@redhat.com>
- update to 2.2.13

* Mon Jun 25 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.12-2
- rebuild

* Sun Jun 24 2007 Nalin Dahyabhai <nalin@redhat.com> - 2.2.12-1
- update to 2.2.12

* Sun Oct 01 2006 Jesse Keating <jkeating@redhat.com> - 2.2.11-2
- rebuilt for unwind info generation, broken in gcc-4.1.1-21

* Thu Sep 21 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.11-1
- update to 2.2.11

* Wed Sep 13 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.10-1
- build

* Tue Sep 12 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.10-0.1
- revert previous changes to how prompting works, and add a
  no_subsequent_prompt option to suppress libkrb5-based prompts during
  authentication, providing the PAM_AUTHTOK for all questions which
  libkrb5 asks

* Fri Sep  8 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.10-0
- rework prompting so that we stop getting stray prompts every now and then,
  and so that use_first_pass will *never* prompt for any information

* Tue Jul 25 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.9-1
- return PAM_IGNORE instead of PAM_SERVICE_ERR when we're called in
  an unsafe situation and told to refresh credentials (#197428)
- drop from setuid to "normal" before calling our storetmp helper, so that
  it doesn't freak out except when *it* is setuid (#190159)
- fix handling of "external" cases where the forwarded creds don't belong to
  the principal name we guessed for the user (#182239,#197660)

* Mon Jul 17 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.8-1.2
- rebuild

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 2.2.8-1.1
- rebuild

* Wed Mar 29 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.8-1
- don't try to validate creds in a password-changing situation, because the
  attempt will always fail unless the matching key is in the keytab, which
  should never be the case for the password-changing service (#187303, rbasch)
- if v4 has been disabled completely, go ahead and try to set 2b tokens
  because we're going to end up having to do that anyway (#182378)

* Fri Mar 10 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.7-2
- fixup man page conflicts in %%install

* Wed Mar  8 2006 Bill Nottingham <notting@redhat.com> - 2.2.6-2.2
- don't use paths in man pages - avoids multilib conflicts

* Tue Feb 21 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.7-1
- add v4 credential conversion for "use_shmem" and "external" cases (though
  it should be redundant with "use_shmem") (#182239)

* Mon Feb 13 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.6-2
- rebuild

* Mon Feb  6 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.6-1
- add a "krb4_use_as_req" option so that obtaining v4 creds kinit-style can
  be disabled completely (Hugo Meiland)

* Thu Jan 26 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.5-1
- don't log debug messages that we're skipping session setup/teardown unless
  debugging is enabled (#179037)
- try to build the module with -Bsymbolic if we can figure out how to do that

* Tue Jan 17 2006 Nalin Dahyabhai <nalin@redhat.com>
- include the NEWS file as documentation

* Mon Jan 16 2006 Nalin Dahyabhai <nalin@redhat.com> - 2.2.4-1
- fix reporting of the exact reason why a password change failed

* Mon Dec 19 2005 Nalin Dahyabhai <nalin@redhat.com> - 2.2.3-1
- fix a compile problem caused by a missing #include (Jesse Keating)

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com> - 2.2.2-1.3
- rebuilt

* Mon Nov 21 2005 Nalin Dahyabhai <nalin@redhat.com> - 2.2.2-1
- don't leak the keytab descriptor during validation (#173681)

* Tue Nov 15 2005 Nalin Dahyabhai <nalin@redhat.com> - 2.2.1-1
- update to 2.2.1

* Fri Nov 11 2005 Nalin Dahyabhai <nalin@redhat.com> - 2.2.0-2
- rebuild

* Fri Nov 11 2005 Nalin Dahyabhai <nalin@redhat.com> - 2.2.0-1
- update to 2.2.0

* Wed Oct  5 2005 Nalin Dahyabhai <nalin@redhat.com> - 2.1.95-0
- update to 2.1.95

* Mon Aug 30 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.1.2-1
- update to 2.1.2

* Mon Jun 21 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.1.1-1
- update to 2.1.1

* Wed Apr 21 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.1.0-1
- update to 2.1.0

* Tue Mar 23 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.0.11-1
- update to 2.0.11

* Tue Mar 16 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.0.10-1
- update to 2.0.10

* Tue Mar 16 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.0.9-1
- update to 2.0.9

* Tue Mar 16 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.0.8-1
- update to 2.0.8

* Wed Mar 10 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.0.7-1
- update to 2.0.7

* Fri Feb 27 2004 Nalin Dahyabhai <nalin@redhat.com> - 2.0.6-1
- update to 2.0.6

* Tue Feb 24 2004 Harald Hoyer <harald@redhat.com> - 2.0.5-3
- rebuilt

* Tue Nov 25 2003 Nalin Dahyabhai <nalin@redhat.com> 2.0.5-2
- actually changelog the update to 2.0.5

* Tue Nov 25 2003 Nalin Dahyabhai <nalin@redhat.com> 2.0.5-1
- update to 2.0.5

* Fri Oct 10 2003 Nalin Dahyabhai <nalin@redhat.com> 2.0.4-1
- update to 2.0.4

* Fri Sep 19 2003 Nalin Dahyabhai <nalin@redhat.com> 2.0.3-1
- update to 2.0.3

* Fri Sep  5 2003 Nalin Dahyabhai <nalin@redhat.com> 2.0.2-1
- update to 2.0.2

* Thu Aug 14 2003 Nalin Dahyabhai <nalin@redhat.com> 2.0.1-1
- update to 2.0.1

* Fri Aug  8 2003 Nalin Dahyabhai <nalin@redhat.com> 2.0-1
- update to 2.0

* Thu Jan 30 2003 Nalin Dahyabhai <nalin@redhat.com> 1.60-1
- fix uninitialized pointer crash reading cached return values

* Wed Jan 29 2003 Nalin Dahyabhai <nalin@redhat.com> 1.59-1
- fix crash with per-user stashes and return values

* Tue Jan 28 2003 Nalin Dahyabhai <nalin@redhat.com> 1.58-1
- fix configure to not link with both libk5crypto and libcrypto

* Mon Jan 27 2003 Nalin Dahyabhai <nalin@redhat.com> 1.57-1
- force -fPIC
- add --with-moduledir, --with-krb5-libs, --with-krbafs-libs to configure
- add per-user stashes and return values

* Tue May 28 2002 Nalin Dahyabhai <nalin@redhat.com> 1.56-1
- guess a default cell name
- fix what's hopefully the last parser bug

* Thu May 16 2002 Nalin Dahyabhai <nalin@redhat.com> 1.55-2
- rebuild in new environment

* Mon Mar 25 2002 Nalin Dahyabhai <nalin@redhat.com> 1.55-1
- handle account management for expired accounts correctly

* Wed Mar 20 2002 Nalin Dahyabhai <nalin@redhat.com> 1.54-1
- reorder configuration checks so that setting afs_cells will properly
  force krb4_convert on

* Wed Mar 20 2002 Nalin Dahyabhai <nalin@redhat.com> 1.53-1
- fix what's hopefully the last parser bug

* Mon Mar 18 2002 Nalin Dahyabhai <nalin@redhat.com> 1.52-1
- apply patch from David Howells to add retain_tokens option

* Thu Mar  7 2002 Nalin Dahyabhai <nalin@redhat.com> 1.51-1
- fix what's hopefully the last parser bug

* Sat Feb 23 2002 Nalin Dahyabhai <nalin@redhat.com> 1.50-3
- rebuild

* Wed Feb 20 2002 Nalin Dahyabhai <nalin@redhat.com> 1.50-2
- rebuild in new environment

* Fri Feb 15 2002 Nalin Dahyabhai <nalin@redhat.com> 1.50-1
- documentation updates (no code changes)

* Tue Feb 12 2002 Nalin Dahyabhai <nalin@redhat.com> 1.49-1
- set PAM_USER using the user's parsed name, converted back to a local name
- add account management service (checks for key expiration and krb5_kuserok())
- handle account expiration errors

* Fri Jan 25 2002 Nalin Dahyabhai <nalin@redhat.com> 1.48-1
- autoconf fixes

* Fri Oct 26 2001 Nalin Dahyabhai <nalin@redhat.com> 1.47-2
- bump release number and rebuild to link with new version of krbafs

* Tue Sep 25 2001 Nalin Dahyabhai <nalin@redhat.com> 1.47-1
- fix parsing of options which have multiple whitespace-separated values,
  like afs_cells

* Wed Sep  5 2001 Nalin Dahyabhai <nalin@redhat.com> 1.46-1
- link with libresolv to get res_search, tip from Justin McNutt, who
  built it statically
- explicitly link with libdes425
- handle cases where getpwnam_r fails but still sets the result pointer
- if use_authtok is given and there is no authtok, error out

* Mon Aug 27 2001 Nalin Dahyabhai <nalin@redhat.com> 1.45-1
- set the default realm when a default realm is specified

* Thu Aug 23 2001 Nalin Dahyabhai <nalin@redhat.com> 1.44-1
- only use Kerberos error codes when there is no PAM error yet

* Wed Aug 22 2001 Nalin Dahyabhai <nalin@redhat.com> 1.43-1
- add minimum UID support (#52358)
- don't link pam_krb5 with libkrbafs
- make all options in krb5.conf available as PAM config arguments

* Tue Jul 31 2001 Nalin Dahyabhai <nalin@redhat.com>
- merge patch from Chris Chiappa for building with Heimdal

* Mon Jul 24 2001 Nalin Dahyabhai <nalin@redhat.com>
- note that we had to prepend the current directory to a given path in
  dlopen.c when we had to (noted by Onime Clement)

* Tue Jul 17 2001 Nalin Dahyabhai <nalin@redhat.com> 1.42-1
- return PAM_NEW_AUTHTOK_REQD when attempts to get initial credentials
  fail with KRB5KDC_ERR_KEY_EXP (noted by Onime Clement)

* Thu Jul 12 2001 Nalin Dahyabhai <nalin@redhat.com>
- add info about accessing the CVS repository to the README
- parser cleanups (thanks to Dane Skow for a more complicated sample)

* Wed Jul 11 2001 Nalin Dahyabhai <nalin@redhat.com>
- buildprereq the krbafs-devel package

* Fri Jul  6 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't set forwardable and assorted other flags when getting password-
  changing service ticket (noted, and fix supplied, by Onime Clement)
- try __posix_getpwnam_r on Solaris before we try getpwnam_r, which may
  or may not be expecting the same number/type of arguments (noted by
  Onime Clement)
- use krb5_aname_to_localname to convert the principal to a login name
  and set PAM_USER to the result when authenticating
- some autoconf fixes for failure cases

* Wed Jun 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- use krb5_change_password() to change passwords

* Tue Jun 12 2001 Nalin Dahyabhai <nalin@redhat.com>
- use getpwnam_r instead of getpwnam when available

* Fri Jun  8 2001 Nalin Dahyabhai <nalin@redhat.com>
- cleanup some autoconf checks

* Thu Jun  7 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't call initialize_krb5_error_table() or initialize_ovk_error_table()
  if they're not found at compile-time (reported for RHL 6.x by Chris Riley)

* Thu May 31 2001 Nalin Dahyabhai <nalin@redhat.com>
- note that [pam] is still checked in addition to [appdefaults]
- note that AFS and Kerberos IV support requires working Kerberos IV
  configuration files (i.e., kinit -4 needs to work) (doc changes
  suggested by Martin Schulz)

* Tue May 29 2001 Nalin Dahyabhai <nalin@redhat.com>
- add max_timeout, timeout_shift, initial_timeout, and addressless options
  (patches from Simon Wilkinson)
- fix the README to document the [appdefaults] section instead of [pam]
- change example host and cell names in the README to use example domains

* Wed May  2 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't delete tokens unless we're also removing ticket files (report and
  patch from Sean Dilda)
- report initialization errors better

* Thu Apr 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- treat semicolons as a comment character, like hash marks (bug reported by
  Greg Francis at Gonzaga University)
- use the [:blank:] equivalence class to simplify the configuration file parser
- don't mess with the real environment
- implement mostly-complete aging support

* Sat Apr  7 2001 Nalin Dahyabhai <nalin@redhat.com>
- tweak the man page (can't use italics and bold simultaneously)

* Fri Apr  6 2001 Nalin Dahyabhai <nalin@redhat.com>
- restore the default TGS value (#35015)

* Wed Mar 28 2001 Nalin Dahyabhai <nalin@redhat.com>
- fix a debug message
- fix uninitialized pointer error

* Mon Mar 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't fail to fixup the krb5 ccache if something goes wrong obtaining
  v4 credentials or creating a krb4 ticket file (#33262)

* Thu Mar 22 2001 Nalin Dahyabhai <nalin@redhat.com>
- fixup the man page
- log return code from k_setpag() when debugging
- create credentials and get tokens when setcred is called for REINITIALIZE

* Wed Mar 21 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't twiddle ownerships until after we get AFS tokens
- use the current time instead of the issue time when storing v4 creds, since
  we don't know the issuing host's byte order
- depend on a PAM development header again instead of pam-devel

* Tue Mar 20 2001 Nalin Dahyabhai <nalin@redhat.com>
- add a separate config file parser for compatibility with settings that
  predate the appdefault API
- use a version script under Linux to avoid polluting the global namespace
- don't have a default for afs_cells
- need to close the file when we succeed in fixing permissions (noted by
  jlkatz@eos.ncsu.edu)

* Mon Mar 19 2001 Nalin Dahyabhai <nalin@redhat.com>
- use the appdefault API to read krb5.conf if available
- create v4 tickets in such a way as to allow 1.2.2 to not think there's
  something fishy going on

* Tue Feb 13 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't log unknown user names to syslog -- they might be sensitive information

* Fri Feb  9 2001 Nalin Dahyabhai <nalin@redhat.com>
- handle cases where krb5_init_context() fails

* Wed Jan 17 2001 Nalin Dahyabhai <nalin@redhat.com>
- be more careful around memory allocation (fixes from David J. MacKenzie)

* Mon Jan 15 2001 Nalin Dahyabhai <nalin@redhat.com>
- no fair trying to make me authenticate '(null)'

* Tue Dec  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- rebuild in new environment

* Fri Dec  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- rebuild in new environment

* Wed Nov  8 2000 Nalin Dahyabhai <nalin@redhat.com>
- only try to delete ccache files once
- ignore extra data in v4 TGTs, but log that we got some
- require "validate" to be true to try validating, and fail if validation fails

* Thu Oct 19 2000 Nalin Dahyabhai <nalin@redhat.com>
- catch and ignore errors reading keys from the keytab (for xscreensaver, vlock)

* Wed Oct 18 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix prompting when the module's first in the stack and the user does not have
  a corresponding principal in the local realm
- properly implement TGT validation
- change a few non-error status messages into debugging messages
- sync the README and the various man pages up

* Mon Oct  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix "use_authtok" logic when password was not set by previous module
- require pam-devel to build

* Sun Aug 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix errors with multiple addresses (#16847)

* Wed Aug 16 2000 Nalin Dahyabhai <nalin@redhat.com>
- change summary

* Thu Aug 10 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix handling of null passwords

* Wed Jul  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- fixes for Solaris 7 from Trevor Schroeder

* Tue Jun 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- add Seth Vidal's no_user_check flag
- document no_user_check and skip_first_pass options in the man pages
- rebuild against Kerberos 5 1.2 (release 15)

* Mon Jun  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- move man pages to %{_mandir}

* Wed May 17 2000 Nalin Dahyabhai <nalin@redhat.com>
- Make errors chown()ing ccache files non-fatal if (getuid() != 0), suggested
  by Steve Langasek.

* Mon May 15 2000 Nalin Dahyabhai <nalin@redhat.com>
- Attempt to get initial Kerberos IV credentials when we get Kerberos 5 creds

* Thu Apr 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- Chris Chiappa's modifications for customizing the ccache directory

* Wed Apr 19 2000 Nalin Dahyabhai <nalin@redhat.com>
- Mark Dawson's fix for krb4_convert not being forced on when afs_cells defined

* Thu Mar 23 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix problem with leftover ticket files after multiple setcred() calls

* Mon Mar 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- add proper copyright statements
- save password for modules later in the stack

* Fri Mar 03 2000 Nalin Dahyabhai <nalin@redhat.com>
- clean up prompter

* Thu Mar 02 2000 Nalin Dahyabhai <nalin@redhat.com>
- add krbafs as a requirement

* Fri Feb 04 2000 Nalin Dahyabhai <nalin@redhat.com>
- pick up non-afs PAM config files again

* Wed Feb 02 2000 Nalin Dahyabhai <nalin@redhat.com>
- autoconf and putenv() fixes for broken apps
- fix for compressed man pages

* Fri Jan 14 2000 Nalin Dahyabhai <nalin@redhat.com>
- tweak passwd, su, and vlock configuration files

* Fri Jan 07 2000 Nalin Dahyabhai <nalin@redhat.com>
- added both modules to spec file

* Wed Dec 22 1999 Nalin Dahyabhai <nalin@redhat.com>
- adapted the original spec file from pam_ldap
