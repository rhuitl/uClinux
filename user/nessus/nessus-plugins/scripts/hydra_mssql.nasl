#TRUSTED 1b294764297ab4d053690a2c985aad4de231eee4d41f2f6fdd1f387ebe323a5794726bb70f8ab804ce6246f04826617a851f44713549033b04565183932b2567101d2aef8e61f188b4b4787942722fc9bf0276ad336e992fa4a1168d7b69af26f31c2cdb91e320bb6bc7077171814c69aeeb6fcfaf82b390a9772f66302d742436371659ada0c21447ee6d02b0b59be176588b4b7f1d6c7eb20090dbf3160e217b895538d461a0815d104ec56bfcfb4776ddf0256554213ff515ff3c18e756f82b0c1d4eaff85c799ec5fed7cb8a2fac1aa4ad05ea15db029049e1e27e04a814ce45be7cf4734593b7fb32ae9a9b449dc4a1db0ff12401c738cfa28eba4a042270a332bf2d079f1c1efe3c590d6cf4474d781522ef656b7bcfc950fd3562f0f8466a15f6d1e94025ea64dd450d1d7b5f5bdb5bedf1eef1129eaa3d3095401ae65b027cdf6c03f88dfa4a2fe210bab6d66b268d9b3d30818d7d644f10ad952a86b9bd9064268d5c5d37a046795896d2eb913e0eaa58c57bb1814be0664e7466d43a3572cb43410fc21ae219309b8537adab0ebd3fbc204b65c05c625cdc650faa676b5f197f8223b228aaa2547385d21e43443e48648c8016539220599764c91d36be7f9c5a47e560069e3c91dbaf116f67e0ce2f56750090b63a6f56dc3468986f05443b2daee67c124a41ef76b9276e9b6e419af55b56d79be99ddf48972ad1
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15878);
 script_version ("1.2");
 name["english"] = "Hydra: MS SQL";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find MS SQL passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force MS SQL authentication with Hydra";
 script_summary(english:summary["english"]);
 script_timeout(0);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/mssql", 1433);
 script_dependencies("hydra_options.nasl", "find_service.nes", "mssqlserver_detect.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/mssql");
if (! port) port = 1433;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

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
argv[i++] = "mssql";

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
    set_kb_item(name: 'Hydra/mssql/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following MS SQL accounts:\n' + report);
