# -*- Fundamental -*-
# (C) 2004 Michel Arboi <mikhail@nessus.org>


# http://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
# [epoch:]upstream_version[-debian_revision]

include('global_settings.inc');

function deb_str_cmp(s1, s2)
{
 local_var	v1, v2;

 while (s1 || s2)
 {
  v1 = eregmatch(string: s1, pattern: "^([^0-9]*)([0-9]*)(.*)$");
  v2 = eregmatch(string: s2, pattern: "^([^0-9]*)([0-9]*)(.*)$");
  if (v1[1] < v2[1])
   return -1;
  else if (v1[1] > v2[1])
   return 1;
  if (v1[2] != v2[2]) return int(v1[2]) - int(v2[2]);
  s1 = v1[3]; s2 = v2[3];
 }
 return 0;
}

function deb_ver_cmp(ver1, ver2)
{
 local_var	v1, v2, e1, e2, uv1, uv2, dr1, dr2, x;

 v1 = eregmatch(string: ver1, pattern: "^([0-9]+:)?(.+)(-([a-z0-9+.]+))?$", icase: 1);
 v2 = eregmatch(string: ver2, pattern: "^([0-9]+:)?(.+)(-([a-z0-9+.]+))?$", icase: 1);
 if (isnull(v1) || isnull(v2)) return;
 e1 = int(v1[1]); uv1 = v1[2]; dr1 = v1[4];
 e2 = int(v2[1]); uv2 = v2[2]; dr2 = v2[4];

 if (e1 != e2) return e1 - e2;
 x = deb_str_cmp(s1: uv1, s2: uv2);
 if (x) return x;
 x = deb_str_cmp(s1: dr1, s2: dr2);
 return x; 
}


function deb_check(prefix, release, reference)
{
 local_var debver, dpkg_l, pkgver;
 local_var installed, ver, v;

 debver = chomp(get_kb_item("Host/Debian/release"));
 if ( ! debver ) return 0; # Not debian

# Try something smarter but slower below
## if (debver && release != debver) return 0;

 dpkg_l = get_kb_item("Host/Debian/dpkg-l");
 installed = egrep(string: dpkg_l, pattern: '^ii +' + prefix + ' +');
 if (! installed) return 0;
 ver = ereg_replace(	string: installed, replace: "\1",
			pattern: '^ii +' + prefix + ' +([^ ]+) +.*$');
 if (ver == installed) return 0;	# cannot extract version

# Here, we try to extract the "branch" from the installed package
# I don't think that mixing sarge, woody and sid packages on a single
# system is great, but it is possible.
# However, the branch is not always included in the package name, and
# Look at "DSA 865-1" for example. So we fall back to /etc/debian-release
# and hope that such mix did not occur

 if (ereg(string: ver, pattern: '[0-9]$')) pkgver = '3.1';
 else if (ereg(string: ver, pattern: 'woody[0-9]$')) pkgver = '3.0';
 else if (ereg(string: ver, pattern: 'potato[0-9]$')) pkgver = '2.2';
 else if (ereg(string: ver, pattern: 'hamm[0-9]$')) pkgver = '2.0';
 else pkgver = debver;

 if (pkgver && release != pkgver) return 0;

 if (deb_ver_cmp(ver1: ver, ver2: reference) < 0)
 {
   debug_print("debian_package[", get_host_ip(), "]: package ", prefix, "_", ver, " is vulnerable in Debian ", release, ". Upgrade to ", prefix, "_", reference, "\n");
   return 1;
 }
 return 0;
}

