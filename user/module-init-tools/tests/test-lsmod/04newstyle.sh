#! /bin/sh

MODTEST_OVERRIDE1=/proc/modules
MODTEST_OVERRIDE_WITH1=tests/tmp/newproc

export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

# new style has dependencies like: "name size usecount [dep],[dep] [other]"
echo 'foo 100 0 -' > tests/tmp/newproc
echo 'bar 101 1 -' >> tests/tmp/newproc
echo 'baz 102 1 baz_dep,' >> tests/tmp/newproc
echo 'bazz 2147483648 2147483648 bazz_dep,bazz_dep2,' >> tests/tmp/newproc
echo 'fuzz 104 1 fuzz_dep,[permenant],' >> tests/tmp/newproc
echo 'fuzzy 105 1 fuzzy_dep,[permenant],[unsafe],' >> tests/tmp/newproc
echo 'fuzzier 106 0 [permenant],[unsafe],' >> tests/tmp/newproc
echo 'newstyle 107 0 - unknownfield' >> tests/tmp/newproc
echo 'newstyle2 108 0 newstyle2_dep, unknownfield unknownfield2' >> tests/tmp/newproc

# This should be true
[ "`lsmod`" = "Module                  Size  Used by
foo                      100  0 
bar                      101  1 
baz                      102  1 baz_dep
bazz                2147483648  2147483648 bazz_dep,bazz_dep2
fuzz                     104  1 fuzz_dep,[permenant]
fuzzy                    105  1 fuzzy_dep,[permenant],[unsafe]
fuzzier                  106  0 [permenant],[unsafe]
newstyle                 107  0 
newstyle2                108  0 newstyle2_dep" ]
