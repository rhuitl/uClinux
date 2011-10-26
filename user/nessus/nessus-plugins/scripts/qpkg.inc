# -*- sh -*-
# This script is copyright 2004 Michel Arboi <mikhail@nessus.org>
# $Revision: 1.16 $

include('global_settings.inc');

global_var	qpkg_list;

# Retuns 1 if surely matches, -1 if surely does not match, NULL or 0 otherwise
function qpkg_ver_cmp(ver, ref, op)
{
  local_var	inf, sup, eq;
  local_var	r, v, i, n, nr, nv;
  local_var     ref_base, ref_r, ver_base, ver_r;
  local_var     vab, vabN, vN, rab, rabN, rN; 
 

  #display('qpkg_ver_cmp: ver=', ver, ' ref=', ref, ' op=', op, '\n');

  # Easy cases: identity
  if (op == 'eq')
   if (ver == ref) return 1; else return -1;
  if (ver == ref)
    if ('e' >< op) return 1; else return -1;

  if ('l' >< op) { inf = 1; sup = -1; } else { inf = -1; sup = 1; }
  if ('e' >< op) { eq = 1; } else { eq = -1; }

  # -r0 treatement
  v = eregmatch(string: ref, icase: 0, pattern: '^(.+)-r([0-9]+)+$');
  if (isnull(v)) { ref_base = ref; ref_r = 0; }
  else { ref_base = v[1]; ref_r = int(v[2]); }

  v = eregmatch(string: ver, icase: 0, pattern: '^(.+)-r([0-9]+)$');
  if (isnull(v)) { ver_base = ver; ver_r = 0; }
  else { ver_base = v[1]; ver_r = int(v[2]); }

  if (ver_base == ref_base)
    if  (ver_r < ref_r) return inf;
    else if (ver_r == ref_r) return eq;
    else return sup;
  # We have remove -r* at the end of the strings

  # alpha / beta
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)_(alpha|beta)([0-9]+)$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)_(alpha|beta)([0-9]+)$');
  if (! isnull(v)) { ver_base = v[1]; vab = v[2]; vabN = int(v[3]); }
  if (! isnull(r)) { ref_base = r[1]; rab = r[2]; rabN = int(r[3]); }
  if (ver_base == ref_base)
  {
    # I supose that 1.30 is newer than 1.30_alpha3
    if (! vab) vab = 'zzzz';
    if (! rab) rab = 'zzzz';
    if (vab < rab) return inf;
    else if (vab > rab) return sup;
    if (vabN < rabN) return inf;
    else if (vabN > rabN) return sup;
  }
  # _alpha* has been removed

  # _pre*
  # The result will probably be wrong if we compare 1.30_pre1 and 1.30_pre20020319
  # but how are we supposed to solve such a case?
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)_pre([0-9]+)$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)_pre([0-9]+)$');
  if (! isnull(v)) { ver_base = v[1]; vN = int(v[2]); }
  if (! isnull(r)) { ref_base = r[1]; rN = int(r[2]); }
  if (ver_base == ref_base)
  {
    # I supose that 1.30 is newer than 1.30_pre20020318
    if (! vN && rN) return sup;
    if (vN && ! rN) return inf;

    if (vN < rN) return inf;
    else if (vN > rN) return sup;
  }

  # _p*
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)_p([0-9]+)$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)_p([0-9]+)$');
  if (! isnull(v)) { ver_base = v[1]; vN = int(v[2]); }
  if (! isnull(r)) { ref_base = r[1]; rN = int(r[2]); }
  if (ver_base == ref_base)
  {
    # 1.30_p2 is newer than 1.30
    if (vN < rN) return inf;
    else if (vN > rN) return sup;
  }

  # _rc*
  v = eregmatch(string: ver_base, icase: 0, pattern: '^(.+)_rc([0-9]+)$');
  r = eregmatch(string: ref_base, icase: 0, pattern: '^(.+)_rc([0-9]+)$');
  if (! isnull(v)) { ver_base = v[1]; vN = int(v[2]); }
  if (! isnull(r)) { ref_base = r[1]; rN = int(r[2]); }
  if (ver_base == ref_base)
  {
    # I supose that 1.30_rc3 is older than 1.30
    if (! vN && rN) return sup;
    if (vN && ! rN) return inf;

    if (vN < rN) return inf;
    else if (vN > rN) return sup;
  }

  # Date
  # Some packages use something like "2004.10.1"
  # Change "2004.10.1" into "2004.10.01" 
  if (ref_base =~ "^((19|20)[0-9]{2})\.([0-9]{2})\.([0-9])$")
    ref_base = strcat(substr(ref_base, 0, 7), '0', substr(ref_base, 8));
  if (ver_base =~ "^((19|20)[0-9]{2})\.([0-9]{2})\.([0-9])$")
    ver_base = strcat(substr(ver_base, 0, 7), '0', substr(ver_base, 8));
  #display('ver_base=', ver_base, ' ref_base=', ref_base, '\n');

  if (op[0] != 'r') # special case for rge, rlt...
  if (ref_base =~ "^(19|20)[0-9]{2}\.?[0-9]{2}\.?[0-9]{2}$")
    if (ver_base !~ "^[12][90][0-9]{2}\.?[0-9]{2}\.?[0-9]{2}$")
    {
      #display("qpkg_ver_cmp: do not know how to compare a date to something else\n");
      return;
    }
    else
    {
      ref_base = int(str_replace(string: ref_base, find: ".", replace: ""));
      ver_base = int(str_replace(string: ver_base, find: ".", replace: ""));
      #display('Comparing dates: ver=', ver_base, ' ref=', ref_base, '\n');
      if (ver_base < ref_base) return inf;
      else if (ver_base > ref_base) return sup;
      else return eq;
    }

  # Simple number
  if (op[0] != 'r') # special case for rge, rlt...
  if (ver_base =~ '^[0-9]+$' && ref_base =~ '^[0-9]+$')
  {
    #display('Comparing numbers: ver=', ver_base, ' ref=', ref_base, '\n');
    v = int(ver_base); r = int(ref_base);
    if (v < r) return inf;
    else if (v > r) return sup;
    else if (v == r) return eq;
  }

  # Clasic version number
  if (ver_base =~ "^[0-9.]+" && ref_base =~ "^[0-9.]+")
  {
    #display('Comparing versions: ver=', ver_base, ' ref=', ref_base, '\n');
    v = split(ver_base, sep: '.');
    r = split(ref_base, sep: '.');
    nv = max_index(v); nr = max_index(r);
    if (nv < nr) n = nv; else n = nr;

    # special case for rge, rlt...
    if (op[0] == 'r' && v[0] != r[0]) return -1;

    for (i = 0; i < n; i ++)
     if (int(v[i]) < int(r[i])) return inf;
     else if (int(v[i]) > int(r[i])) return sup;
    # 1.6.3.1 > 1.6.3
    if (nv < nr) return inf;
    else if (nv > nr) return sup;
    # if (v[i-1] == r[i-1]) return eq; - treated above
    # 2.30 and 2.30b (should I process this like alpha/beta or -r* ?
    v = eregmatch(string: ver_base, pattern: "^[0-9.]+([a-z]?)$");
    r = eregmatch(string: ref_base, pattern: "^[0-9.]+([a-z]?)$");
    if (! isnull(v) && ! isnull(r))
      if (v[1] < r[1]) return inf;
      else if (v[1] > r[1]) return sup;
      else if (v[1] == r[1]) return eq;
  }

  #display("qpkg_ver_cmp: do not known how to compare  ", ver, " ",op, " ", ref, "\n");
  return;
}

function qpkg_cmp(pkg, version, range)
{
  local_var	v, cmp, ver, from_qpkg, l, ret, p, f;

  if (isnull(range)) return;
#display("version=", version, "\trange=", range, "\n");
  v = split(range, sep: ' ');
  if (max_index(v) != 2)
  {
    #display("qpkg_cmp: bad format: ", range, "\tV=", v, "\n"); 
    return;
  }
  cmp = chomp(v[0]); ver = chomp(v[1]);
#display("cmp=", cmp, "\tver=", ver, "\n");
  ret = qpkg_ver_cmp(ver: version, ref: ver, op: cmp);
#  if (ret > 0) display(version, " ", cmp, " ", ver, "\n");
  return ret;
}

function qpkg_check(package, vulnerable, unaffected, arch)
{
  local_var	fU, fV, l, v, name, ver, my_arch, ret, from_qpkg, p, f;

  if (! qpkg_list) qpkg_list = get_kb_item("Host/Gentoo/qpkg-list");
  my_arch = get_kb_item("Host/Gentoo/arch");
  # Debug
  if (COMMAND_LINE && ! qpkg_list && islocalhost())
    qpkg_list = pread(cmd: "qpkg", argv: make_list("qpkg", "-nc", "-I", "-v"));
  if (! qpkg_list) { return; }

  if (arch && my_arch && my_arch >!< arch) return 0;

  l = egrep(string: qpkg_list, pattern: strcat(package, "-[0-9]"));
  # several version of a same package may be installed
  ret = NULL;
  foreach from_qpkg (split(l, keep:0))
  {
     v = eregmatch(string: from_qpkg, icase: 1,
             pattern: '^[a-z0-9-]+/([a-z_-]|[^-][0-9])+-([0-9a-z._-]+)$');
     if (isnull(v))
     {
       #display("qpkg_check: cannot parse ", from_qpkg, "\n");
       # continue does not exist in 2.0.x and will do a parse error
     }
     else
     {
     name = v[1]; ver = v[2];

     foreach p (vulnerable)
     {
        fV = NULL; fU = NULL;

        f = qpkg_cmp(pkg: from_qpkg, version: ver, range: p);
        if (f == 1)
        {
          #display("vulnerable: ", p, "\n");
          fV = 1;
          debug_print(level: 2, 'Gentoo package ', from_qpkg, ' could be vulnerable\n');
          break;
        }
        if (isnull(fV)) fV = f;
      }

     foreach p (unaffected)
     {
        f = qpkg_cmp(pkg: from_qpkg, version: ver, range: p);
        if (f == 1)
        {
          #display("unaffected: ", p, "\n");
          fU = 1;
          debug_print(level: 2, 'Gentoo package ', from_qpkg, ' is not vulnerable\n');
          break;
        }
        if (isnull(fU)) fU = f;
      }
     if (fV > 0 && fU < 1)
     {
      log_print('Gentoo package ', from_qpkg, ' is vulnerable\n');
      return 1;
     }
    }
   }
  return 0;
}
