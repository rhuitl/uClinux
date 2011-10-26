#
# $Id: aix.inc,v 1.2 2005/03/17 18:54:28 npouvesle Exp $
#
# (C) Tenable Network Security
#
# aix_check_patch() returns :
#	-1 if a patch is missing
#	0  if a patch is not installed but not required (ie: other architecture)
#	1 if the patch is installed
#
# example : aix_check_patch("5.1", "IY55678", "devices.scsi.tape.rte.5.1.0.50 devices.scsi.tape.diag.5.1.0.50");
function aix_check_patch(release, patch, package) 
{
 local_var showrev, v, flag, packages, p, pattern;

 packages = get_kb_item("Host/AIX/lslpp");
 showrev = get_kb_item("Host/AIX/version");

 if ( ! packages || ! showrev || !release || !patch || !package) return 0;
 if (release >!< showrev)
   return 0;

 package = split(package, sep:" ", keep:FALSE);
 flag=0;
 foreach p (package)
 {
   p = eregmatch(pattern: "^(.*)\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", string: p, icase: 0);
   pattern = p[1] + ":([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)";
   v = eregmatch(pattern: pattern , string: packages, icase: 0);
   if (!isnull(v))
   {
     flag = 1;
     if (v[1] < p[2])
       return -1;
   }
 }

 if (flag)
   set_kb_item(name: "Host/AIX/"+patch, value:1);

 return flag;
}
