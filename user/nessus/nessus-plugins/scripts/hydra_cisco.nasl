#TRUSTED 0c8ccc7f086cb31af629ee7559794807876470464b1740cfb5b010eb59cf726570fb861d2581738dff21a29b57317da27065dd6d1b2bf31ed1b10313cab5d7bff4da7dcc20b2e3ae2c8b0c55ebd106dcb35fe08a6a5f13be8ce2741a509f4280fc1943c74c0fe850385ec0735f76cf3cb407f7b0d652e49f732a236db2144139c45b68dc287140899bf3c2828faaad504b0b2ebeecd4b078b25152e10b93d1eb3fd2c5f304bc2eb03f330bf795d07125225d9ac65cec7ed7568ae9a5effe6b2a1d73df6a7d1231c2881961deda77c59dd8603dfa990f7383ba270a779cecb72bda2f8326204dcaa21e646d1d2870f5b42a4d06470cb37c67396ca85d59236455ede1192f3cd44980cdae2c50da823102127420a462dc8536822b1eabdab5d5bfcfa8b8ca2d2fba8876e993dac75c7a16bfc733afd78830f7083eba01cb83396fa25663222d434ebd9dfd92d94830406da747826e45aba4b1520422c8b38199031ede752dcac7783396bd2f7d0eb29d1c1ea9d885fb29232a0457732c6d03e873e8cb1ba4bad40bd276033ad34b755fdfd23b6cef53b84ec700e0ecba1ab265645f3b01e661226880c1ef6e42b76db9eb2819e550449335f693e026eeee38b3f829f215f591825756f2335d74769fa5241c725933a4a26fd7ca37bea8d375fabfd2bdae3a8af2f72331e678d58e7e140a7553d6cc337af383201860f6df4f2189
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15869);
 script_version ("1.2");
 name["english"] = "Hydra: Cisco";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find Cisco passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force Cisco authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_timeout(0);
 script_require_keys("Secret/hydra/passwords_file");
 script_require_ports("Services/telnet", 23);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd == NULL) exit(0);

port = get_kb_item("Services/telnet");
if (! port) port = 23;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >!< r) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-P"; argv[i++] = passwd;
if (empty)
{
  argv[i++] = "-e"; argv[i++] = "n";
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
argv[i++] = "cisco";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    # l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/cisco/'+port, value: p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to find the following CISCO passwords:\n' + report);
