# -*- Fundamental -*-
# (C) 2005 Michel Arboi <mikhail@nessus.org>



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

function ubuntu_ver_cmp(ver1, ver2)
{
 local_var	v1, v2, e1, e2, uv1, uv2, dr1, dr2, x;

 ##display("ubuntu_ver_cmp(ver1:", ver1, ", ver2:", ver2, ")\n");

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


function ubuntu_check(osver, pkgname, pkgver)
{
 global_var release, dpkg_l, pkgver;
 local_var installed, ver, v;

 if (! release) release = chomp(get_kb_item("Host/Ubuntu/release"));
 if (release != osver) return NULL;

 if (!dpkg_l) dpkg_l = get_kb_item("Host/Debian/dpkg-l");
 installed = egrep(string: dpkg_l, pattern: '^ii +' + pkgname + ' +');
 if (! installed) return NULL;

 ##display("ubuntu_check(osver:", osver, ", pkgname: ", pkgname, ", pkgver: ", pkgver, "\n");

 ver = ereg_replace(	string: installed, replace: "\1",
			pattern: '^ii +' + pkgname + ' +([^ ]+) +.*$');
 if (ver == installed) return NULL;	# cannot extract version

 if (ubuntu_ver_cmp(ver1: ver, ver2: pkgver) < 0)
   return ver;
 return NULL;
}

