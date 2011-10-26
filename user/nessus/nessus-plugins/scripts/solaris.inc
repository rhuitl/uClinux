#
# (C) Tenable Network Security
#
# $Id: solaris.inc,v 1.4 2006/10/03 16:08:43 renaud Exp $
#

function patch_installed(showrev, patch)
{
 local_var v, p,r,patches,spatches, flag;
 v = split(patch, sep:"-", keep:0);
 patches = egrep(pattern:"^Patch: " + v[0], string:showrev);
 if ( ! patches ) return 0; # No patch
#
# there may be more then one patch version be listed, so split up the result
# and do a foreach check.
#
 spatches = split(patches, keep:0); 
 flag = 0;
 foreach r (spatches)
	{
 	# Get the revision number of the installed patch
 	r = ereg_replace(pattern:"Patch: ([0-9]*-[0-9]*) .*", replace:"\1", string:r);
 	p = split(r, sep:"-", keep:0);
 	# If the installed patch is newer than or equal to what we expect, consider
 	# it installed
 
 	if  ( int(p[1]) >= int(v[1]) ) 
	flag = 1; # Patch is installed
	}
return flag;	
}


#
# solaris_check_patch() returns :
#	-1 if a patch is missing
#	0  if a patch is not installed but not required (ie: other architecture)
#	1 if the patch is installed
#
function solaris_check_patch(release, arch, patch, package, obsoleted_by) 
{
 local_var showrev, r, flag, packages, p;

 if ( "_x86" >< release )
	release -= "_x86";

 packages = get_kb_item("Host/Solaris/pkginfo");
 showrev = get_kb_item("Host/Solaris/showrev");
 if ( ! packages || ! showrev || !release || !patch ) return 0;

 # Look if at least one of the packages installed are affected
 # by this patch
 flag = 0;
 if ( strlen(package) )
 {
  package = split(package, sep:" ", keep:FALSE);
  foreach p (package)
	{
  	if ( egrep(pattern:"^.* " + p + " ", string:packages) ) flag ++;
		}

 } else flag = 1;

 # No package is affected  - return
 if ( flag == 0 ) return 0;


 r = split(release, sep:" ", keep:0);
 flag = 0;
 foreach release (r)
 {
 if ( egrep(pattern:"^Release: " + release, string:showrev) ) flag ++;
 }

 if ( ! flag ) return 0; # Not the right release

 if ( ! egrep(pattern:"^Application architecture: " + arch, string:showrev) ) 
	return 0; # Wrong architecture (intel vs. sparc)

 if ( patch_installed(patch:patch, showrev:showrev) )
	return 1; # Installed

 if ( obsoleted_by && patch_installed(patch:obsoleted_by, showrev:showrev) )
	return 1; # Installed

 return -1; # Not installed
}


