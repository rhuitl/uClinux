# -*- Fundamental -*-
# (C) 2004 Michel Arboi
#
# $Revision: 1.3 $
#

global_var slack_pkg_list, slack_ver;

# Examples of version numbers:
# sendmail-cf-8.12.9
# samba-2.2.8a
# dhcp-3.0pl2
# mod_ssl-2.8.14_1.3.27
# sysvinit-2.84
# kernel-modules-2.4.21
# kernel-modules-2.4.21_xfs
# openssh-3.7.1p1
# openssl-solibs-0.9.7c
# xine-lib-1rc4
# xine-lib-1rc6a
# hotplug-2004_01_05

function slack_elt_cmp(e1, e2)
{
 local_var	y1, y2, m1, m2, c;

 if (e1 == e2) return 0;
 if (isnull(e1))
  return -1;
 else if (isnull(e2))
  return 1;

 y1 = eregmatch(string: e1, pattern: "^([0-9]+)([a-z]*)([0-9]*)$");
 y2 = eregmatch(string: e2, pattern: "^([0-9]+)([a-z]*)([0-9]*)$");
 if (! isnull(y1) || ! isnull(y2))
 {
  m1 = int(y1[1]); m2 = int(y2[1]);
  if (m1 != m2) return m1 - m2;
   
  if (y1[2] < y2[2]) return -1;
  else if (y1[2] > y2[2]) return 1;
  else return int(y1[3]) - int(y2[3]);
 }
 else
 {
  #debug_print("Don't known how to compare '", e1, "' and '", e2, "'\n");
  return 0;
 }
}

function slack_ver_cmp(v1, n1, v2, n2)
{
 local_var	x1, x2, i, m1, m2, m, y1, y2, c;

 n1 = int(n1); n2 = int(n2);
 if (v1 == v2) return n1 - n2;
 if ("." >< v1 && "." >< v2)
 {
  x1 = split(v1, sep: '.', keep: 0);  
  x2 = split(v2, sep: '.', keep: 0);  
  m1 = max_index(v1); m2 = max_index(v2);
  if (m1 > m2) m = m1; else m = m2;
  for (i = 0; i < m; i ++)
  {
   c = slack_elt_cmp(e1: x1[i], e2: x2[i]);
   if (c != 0) return c;
  }
  return 0;
 }	# 1.2.3p4

 x1 = eregmatch(string: v1, pattern: "^([0-9]+)_([0-9]+)_([0-9]+)$");
 x2 = eregmatch(string: v2, pattern: "^([0-9]+)_([0-9]+)_([0-9]+)$");
 if (! isnull(x1) && ! isnull(x2))
 {
  for (i = 1; i < 4; i ++)
  {
   m1 = int(x1[i]); m2 = int(x2[i]);
   if (m1 != m2) return m1 - m2;
  }
  return 0;
 }	# 2004_01_03

 return slack_elt_cmp(e1: v1, e2: v2);
}


function slackware_check(osver, pkgname, pkgver, pkgnum, pkgarch)
{
 local_var ipkg, v, cmp;

 if (! slack_pkg_list) slack_pkg_list = get_kb_item("Host/Slackware/packages");
 if (! slack_ver)
 {
   slack_ver = chomp(get_kb_item("Host/Slackware/release"));
   # Keep only version & sub-version
   slack_ver = ereg_replace(string: slack_ver, icase: 1, replace: "\2",
	pattern: "^(Slackware +)?([0-9]+\.[0-9]+)(\.[0-9]+)?$");
 }
 if (! slack_pkg_list)
 {
   #debug_print("slackware_check: slack_pkg_list is empty\n");
   return 0;
 }
 if (! slack_ver)
 {
   #debug_print("slackware_check: slack_ver is empty\n");
   return 0;
 }
 if (slack_ver != osver)
 {
   #debug_print("slack_ver: slack_ver=", slack_ver, " - osver=", osver, "\n");
   return 0;
 }

 ipkg = chomp(egrep(string: slack_pkg_list, pattern: strcat("^", pkgname, "-[0-9][0-9a-z.+_]+-", pkgarch, "-[0-9]+$")));
 if (! ipkg)
 {
   #debug_print(pkgname, "-", pkkarch, " is not installed\n");
   return 0;	# Not installed
 }
# Cannot use split as pkgname may contain '-'
 v = eregmatch(string: ipkg, pattern: "^(.+)-([^-]+)-([^-]+)-([^-]+)$");
 if (isnull(v))
 {
  #debug_print("cannot parse ", ipkg, "\n");
  return 0;
 }

 if (v[1] != pkgname || v[3] != pkgarch)
 {
   #debug_print("Invalid pkgname (", v[1], "/", pkgname, ") or pkgarch (", v[3], "/", pkgarch, ")\n");
    return 0;	# Bug?
 }
 cmp = slack_ver_cmp(v1: v[2], n1: v[4], v2: pkgver, n2: pkgnum);
 #debug_print("slack_ver_cmp(v1: ", v[2], ", n1: ", v[4], ", v2:", pkgver, ", n2:", pkgnum, ") = ", cmp, "\n");
 return (cmp < 0);
}

