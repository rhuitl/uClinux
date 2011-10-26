#TRUSTED 2d891eadee290144e34d9cc5864d578a0d943246e1ac53e684a0879b3626e9aeb89f2e6052e4d46730a84da3b842abbc4b5fe3a6a158a6389b8b7cf92a5eaac63b8c36402a7de8aa26bacb700176856e4e5fbb02a1c7f9bb484331da0e13b5020a4b75321a2898666277699a79f17cbd9d37cff10426c5c56e325c0fc335e7eda2abed7e44bd3caa955c63c3b1f753e4611bca814773b3c85e53a6bd71aedb9b6ddf3865ede3b8209f57350deb443503ce23d50e779cc214157b2a31b2c15a9885782da98f6b845c0c2fba41e03e396226a4834eb56698b5ee4e225d5aef563b7af772f872b0e7d511f48f8864518c1009a3e9582177ed983d6e1f1e4f78e084ec8e5941ded349242da768524eceb73ae530cd8b67b4bc56cfbb6e02c8eed3f57dbfc6e6904351bf266b91ee9c191853e30ca46052d8d37dcfdf110a38ace9bd3e28e317e7f28eda3b8123b82e936ed2316c14c76fd0bc96e8f34150fd9ecc6c35f73ec5f5f0abec5562629191462e4537a91776f534fdebfe2ac27d3b56bcc3fb35255b6b34cdf45ee2b079b879b7d4b33e588e81e61979ca4a3ccb933e806836ebe9b224b3a227f2ac7dfc368670ec5ff081826bb7df8444ae32332a60c178b1238dec00dd302588cd257f0c408fc59608d441d957a444a2164862aa8e52835aeb6fefc96da1d58f4229fb9af790b8509ecd53dc4666589ff4985a9c776c6f
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
if ( ! defined_func("pread") || ! defined_func("fread") ||
     ! defined_func("get_preference") ) exit(0);
if ( ! find_in_path("amap") ) exit(0);


if(description)
{
 script_id(14663);
 script_version ("1.11");
 name["english"] = "amap (NASL wrapper)";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs amap to find open ports and identify applications.
See the section 'plugins options' to configure it

";

 script_description(english:desc["english"]);
 
 summary["english"] = "Performs portscan / RPC scan / application recognition";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Port scanners";
 family["francais"] = "Scanners de ports";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("ping_host.nasl");

 if (NASL_LEVEL < 2181) exit(0);	# Cannot run

 script_add_preference(name: "File containing machine readable results : ", value: "", type: "file");

 script_add_preference(name:"Mode", type:"radio", value: "Map applications;Just grab banners;Port scan only");
 script_add_preference(name:"Quicker", type:"checkbox", value: "no");
 script_add_preference(name:"UDP scan (disabled in safe_checks)", type:"checkbox", value: "no");
 script_add_preference(name:"SSL (disabled in safe_checks)", type:"checkbox", value: "yes");
 script_add_preference(name:"RPC (disabled in safe_checks)", type:"checkbox", value: "yes");

 script_add_preference(name:"Parallel  tasks", type:"entry", value: "");
 script_add_preference(name:"Connection retries", type:"entry", value: "");
 script_add_preference(name:"Connection timeout", type:"entry", value: "");
 script_add_preference(name:"Read timeout", type:"entry", value: "");

 exit(0);
}

#
function hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);  # remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) display("hex2raw: odd string: ", s, "\n");
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

if (NASL_LEVEL < 2181 || ! defined_func("pread") || ! defined_func("get_preference"))
{
  set_kb_item(name: "/tmp/UnableToRun/14663", value: TRUE);
  display("Script #14663 (amap_wrapper) cannot run - upgrade libnasl\n");
  exit(0);
}

function do_exit()
{
  if (tmpnam) unlink(tmpnam);
}

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++) 
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

res = script_get_preference_file_content("File containing machine readable results : ");
if (res)
  res = egrep(pattern: "^" + esc_ip + ":[0-9]+:", string: res);
if (! res)
{
# No result, launch amap
tmpdir = get_tmp_dir();
if ( ! tmpdir ) do_exit();
tmpnam = strcat(tmpdir, "amap-", get_host_ip(), "-", rand());

p = script_get_preference("UDP scan (disabled in safe_checks)");
if ("yes" >< p)
 udp_n = 1;
else
 udp_n = 0;

n_ports = 0;

for (udp_flag = 0; udp_flag <= udp_n; udp_flag ++)
{
 i = 0;
 argv[i++] = "amap";
 argv[i++] = "-q";
 argv[i++] = "-U";
 argv[i++] = "-o";
 argv[i++] = tmpnam;
 argv[i++] = "-m";
 if (udp_flag) argv[i++] = "-u";

 p = script_get_preference("Mode");
 if ("Just grab banners" >< p) argv[i++] = '-B';
 else if ("Port scan only" >< p) argv[i++] = '-P';
 else argv[i++] = '-A';

 # As all UDP probes are declared harmful, -u is incompatible with -H
 # Amap exits immediatly with a strange error.
 # I let it run just in case some "harmless" probes are added in a 
 # future version

 if (safe_checks()) argv[i++] = "-H";

 p = script_get_preference("Quicker");
 if ("yes" >< p) argv[i++] = "-1";

 # SSL and RPC probes are "harmful" and will not run if -H is set

 p = script_get_preference("SSL (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-S";
 p = script_get_preference("RPC (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-R";

 p = script_get_preference("Parallel  tasks"); p = int(p);
 if (p > 0) { argv[i++] = '-c'; argv[i++] = p; }
 p = script_get_preference("Connection retries"); p = int(p);
 if (p > 0) { argv[i++] = '-C'; argv[i++] = p; }
 p = script_get_preference("Connection timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-T'; argv[i++] = p; }
 p = script_get_preference("Read timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-t'; argv[i++] = p; }

 argv[i++] = ip;
 pr = get_preference("port_range");
 if (! pr) pr = "1-65535";
 foreach p (split(pr, sep: ',')) argv[i++] = p;

 res1 = pread(cmd: "amap", argv: argv, cd: 1, nice: 5);
 res += fread(tmpnam);
 }
}

# IP_ADDRESS:PORT:PROTOCOL:PORT_STATUS:SSL:IDENTIFICATION:PRINTABLE_BANNER:FULL_BANNER

foreach line(split(res))
{
  v = eregmatch(string: line, pattern: '^'+esc_ip+':([0-9]+):([^:]*):([a-z]+):([^:]*):([^:]*):([^:]*):(.*)$');
  if (! isnull(v) && v[3] == "open")
  {
   scanner_status(current: ++ n_ports, total: 65535 * 2);
   proto = v[2];
   port = int(v[1]); ps = strcat(proto, ':', port);
   scanner_add_port(proto: proto, port: port);
   # As amap sometimes give several results on a same port, we save 
   # the outputs and remember the last one for every port
   # The arrays use a string index to save memory
   amap_ident[ps] = v[5];
   amap_ssl[ps] = v[4];
   amap_print_banner[ps] = v[6];
   amap_full_banner[ps] = v[7];

  }
}

if (n_ports != 0)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: 'Host/scanners/amap', value: TRUE);
 if (pr == '1-65535')
   set_kb_item(name: "Host/full_scan", value: TRUE);
}

if (udp_n && n_ports)
  set_kb_item(name: "Host/udp_scanned", value: 1);

scanner_status(current: 65535 * 2, total: 65535 * 2);

function cvtbanner(b)
{
  local_var i, l, x;
  l = strlen(b);

  if (b[0] == '0' && b[1] == 'x')
   return hex2raw(s: substr(b, 2));

  x = "";
  for (i = 0; i < l; i ++)
   if (b[i] != '\\')
    x += b[i];
   else
   {
    i++;
    if (b[i] == 'n') x += '\n';
    else if (b[i] == 'r') x += '\n';
    else if (b[i] == 't') x += '\t';
    else if (b[i] == 'f') x += '\f';
    else if (b[i] == 'v') x += '\v';
    else if (b[i] == '\\') x += '\\';
    else display('cvtbanner: unhandled escape string \\'+b[i]+'\n');
   }
  return x;
}

if (! isnull(amap_ident))
 foreach p (keys(amap_ident))
 {
  v = split(p, sep: ':', keep: 0);
  proto = v[0]; port = int(v[1]);
  if (proto == "tcp")
  {
   soc = open_sock_tcp(port);
   if (soc)
    close(soc);
   else
    security_hole(port: port, data: "Either this port is dynamically allocated
or amap killed this service.
If so, upgrade it!

Risk : None / High\n");
  }
  id = amap_ident[p];
  if (id && id != "unidentified" && id != 'ssl')
  {
   security_note(port: port, proto: proto, data: "Amap has identified this service as " + id);
   set_kb_item(name: "Amap/"+proto+"/"+port+"/Svc", value: id);
  }

  banner = cvtbanner(b: amap_print_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/PrintableBanner", value: banner);

  banner = cvtbanner(b: amap_full_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/FullBanner", value: banner);
 }


do_exit();
