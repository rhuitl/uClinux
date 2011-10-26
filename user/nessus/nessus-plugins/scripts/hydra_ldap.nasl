#TRUSTED 6c9e72e744b87099613ee12fc406a247271bebaeba143c93165ed8108d3f8842f14539832cff82edc0dbab06d632df8fd111561e4262c47c0996da07e6193a117db02ad0ad8baf585b0b856fa8b1a99968f13cbd3000a88187782489cc046b8ca2706d77554f03feed35afae3a4c62185e6442d74ac074a21d7d5eb57531b63bc2002c34fe3aa0081c6651e4fd76fdf980adeaf2fae609c4dd7a81ec518d0d3f4a83041c487bca6ff12198e4140a367bc46c951bc15405fac88681e9b69c4b6573b0dba30cd5c6fb5d4edb80fa523d839cda09020d9e90753fe0581af296f657a5b37a9a858d0594d8c1af19e851b99ecbabb179fc1de68fec6cc7dc93ced06e8acb2a3b7c38133e3f65859f60b5f728c6f8df0a32e78a6848363c19cd03411ffdb66bc234b0974257fdbe910511fad8ce8616c59fe6b8f82332ed1fb9d3405d0358ee5a1c9676420fe0627630b8782d37ac69e87eb2eb45aef58e167eaec306417d9b94ff859df60f4fe80f45847caad87477adb1e163a5d884c9810532465eab2ff076b4082b9d3d1f8a9880ca8b3e52240d3d36827968fcabc369173c2c4a3677e84e2994ec458080369f108c2097efe6c5231da6bcc9ffb71b85435c72c475c806169fd0dd64f195cd553c1aad79ad44fa947a6a0ba68189ff9432507fa18e638b6412071bd48322fd34d25e0243e6715f5d122b5f109bc93db64a0bf178
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15877);
 script_version ("1.3");
 name["english"] = "Hydra: LDAP";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find LDAP accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force LDAP authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "DN : ", type: "entry", value: "");

 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/ldap", 389);
 # find_service does not detect LDAP yet, so we rely upon amap
 # However find_services will detect the SSL layer for LDAPS
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl", "external_svc_ident.nasl", "ldap_detect.nasl");
 exit(0);
}

#

thorough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< thorough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/ldap");
if (! port) port = 389;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

dn = script_get_preference("DN : ");
if (! dn) exit(0);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "ldap";
argv[i++] = dn;

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/ldap/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following accounts on the LDAP server:\n' + report);
