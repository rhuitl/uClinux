#TRUSTED 733759ab0a11998518cea28284efdcce093e05c3d9aa06008ed18fa7847f665c900aa976ecdb1b4b0c0168da5f6c08c4e263612e775f56615f64d98f0121349cecd19d6e8162ed65eda8a27573c1fc6883005bcb863fa927b1472d2fcce055d2d2d0e765aea2656d3dfc5ed96a58184258473a7ac70a1aa1166e61125f6ef4a04433f46dbc8eed4e54aae80962c869f9ab4c169619b069a03fc5daa8e85443c3c051c2b92d6b243ab91ee524f4773fe96f648c5a1bb1e419080e9919b20143270e95aef48ea79fb4e06d138f6bf8db9f45b8e92c7e687c950bc42dd4edc09a01aa9b5de482eba7c3df7acb761e026022ea565746eb747366c716671f981742f0a9df63dce9d9fadd1edb50f54d6287194b00f659a7c8cb5eb263a68c3da775c9d66bbb0370961e04448b614c0432c30bfe1d6c0ca7bcdd222f40cdec6781415a8635f364341b7312de519d15e2e2724873cd6393d6ad14129c17560c3d403104802ca5761b5e057c1a4c886abb9b53d193d255b60fcdf2bd32ccaf385d22dee0f0aa761fa977352fa44621dfff6a2b4306bfedcefbd6d62ed9b9aeaab8b5c735431564ce63fdfed8c2a8c5c50f113ad2ea7221a9dd3d4790f286ca3287f7c71f60ef21277062ee2fa7ff1fa1dc558fd374059d423498a8c0874b2e1826226dc124a8f03ac094c89e1ede4fc03d19d6fae149ed2f1a258457397ddb1307479b5e
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15883);
 script_version ("1.2");
 name["english"] = "Hydra: SAP R3";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find SAP R3 accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force SAP R3 authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_add_preference(name: "Client ID (between 0 and 99) : ", type: "entry", value: "");
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/sap-r3", 3299);
 script_dependencies("hydra_options.nasl", "find_service.nes", "external_svc_ident.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/sap-r3");
if (! port) port = 3299;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

id = script_get_preference("Client ID (between 0 and 99) : ");
if (! id) exit(0);
id = int(id);
if (id < 0 || id > 99) exit(0);

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
argv[i++] = "sapr3";
argv[i++] = id;

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
    set_kb_item(name: 'Hydra/sapr3/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following SAP R3 accounts:\n' + report);
