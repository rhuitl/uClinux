#! /bin/sh

MODTEST_OVERRIDE1=/proc/modules
MODTEST_OVERRIDE_WITH1=tests/tmp/oldproc

export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

# Old style has dependencies like: "name size usecount [dep] [dep]..."
echo 'foo 100 0' > tests/tmp/oldproc
echo 'bar 101 1' >> tests/tmp/oldproc
echo 'baz 102 1 baz_dep' >> tests/tmp/oldproc
echo 'bazz 2147483648 2147483648 bazz_dep bazz_dep2' >> tests/tmp/oldproc
echo 'fuzz 104 1 fuzz_dep [permenant]' >> tests/tmp/oldproc
echo 'fuzzy 105 1 fuzzy_dep [permenant] [unsafe]' >> tests/tmp/oldproc
echo 'fuzzier 106 0 [permenant] [unsafe]' >> tests/tmp/oldproc

[ "`lsmod`" = "Module                  Size  Used by
foo                      100  0 
bar                      101  1 
baz                      102  1 baz_dep
bazz                2147483648  2147483648 bazz_dep bazz_dep2
fuzz                     104  1 fuzz_dep [permenant]
fuzzy                    105  1 fuzzy_dep [permenant] [unsafe]
fuzzier                  106  0 [permenant] [unsafe]" ]

# If CONFIG_MODULE_UNLOAD=n: simply "name size"
echo 'baz 102' > tests/tmp/oldproc
echo 'bazz 2147483648' >> tests/tmp/oldproc

[ "`lsmod`" = "Module                  Size  Used by
baz                      102
bazz                2147483648" ]
