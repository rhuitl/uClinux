#TRUSTED a7288ebb114cedaec6fb8eb0ff06e4c0d99c1fad6f46bc8203b99c4fdc05d459bd2e9234a8cf3679f8086c2a387c1c35d4e4404458468b88b247e71281ba88d00739c86fe49f1168ef1c70f109ec83930fb2424642c7bea7f2389b9980313928be2358c55f331567c2e99187791edcaf618c7415f36f68bcc85bca645c2333bd2816f123cac4824ae1d0d63ad04c889d00dc17fd3e9141aa600ff8b52e51923a11e7934fc765e0d8dabc70f1b2355cc0335ef1f0e4e6964dea3780ffcb1f8737dc89892b7754db6cd252458920cda1c1281831eb70e0286a8a1709fb09be3e5e442664ab408ea6bc2c7671ee079728ac86150a1d65bb22d1e92ba2e7a04e95199a30c011d8a47ba541f2f9b1caff6d03c1a9f8989b5fff50ff73dc018fa4d3edc89d2e41bedec94ad8235153db933421fd33eaaaec4bd42f0fc28f779cd6a7d945e43f3d92effbeaf3ee9962e26754d63cb59eddcb52083f6266da84726a12c41c05c59decc6e6ddbdb03e0464e5b73d38c16ec0d03bc3e0a6e228fea9925015284090be88411a0481a30b53a80c0e5107d79d545b6e4c2ee1e0210b13979685075ca4c7f2a2de12e5aa945edde4bba03ff9abc29f2502d6ff94b720e876c6bf5b006a0ea7afb7d07bfb6fff1397dd42d85b61b1ff24c46756d7697611a62e29550e91411e22ff06ed2f841bdf86d75961d8003336e7bff587e11db448d0efad
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);


if(description)
{
 script_id(15880);
 script_version ("1.2");
 name["english"] = "Hydra: PCNFS";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find PCNFS accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force PCNFS authentication with Hydra";
 script_summary(english:summary["english"]);
 script_timeout(0);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_udp_ports(640);
 script_dependencies("hydra_options.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = 640;
if (! get_udp_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");

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
argv[i++] = "pcnfs";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*)? password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/pcnfs/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following PC-NFS accounts:\n' + report);
