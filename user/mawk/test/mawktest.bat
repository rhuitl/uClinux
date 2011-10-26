echo off
rem  This is a simple test that a new made mawk seems to
rem  be working OK.
rem  It's certainly not exhaustive, but the last two tests in 
rem  particular use most features.
rem 
rem  It needs to be run from mawk/test and mawk needs to be in PATH 
rem
rem  it's too bad that years after MSDOS was introduced that basic
rem  system utilities like fc still don't return valid exit codes!!!

set dat=mawktest.dat
if %CMP%.==. set CMP=cmp

rem  find out which mawk we're testing
..\mawk -Wv

rem ################################

echo testing input and field splitting
..\mawk -f wc.awk %dat% > temp$$
%CMP% temp$$ wc-awk.out
if errorlevel 1 goto :done

rem ####################################

echo testing regular expression matching
..\mawk -f reg0.awk %dat% > temp$$
..\mawk -f reg1.awk %dat% >> temp$$
..\mawk -f reg2.awk %dat% >> temp$$
%CMP% temp$$ reg-awk.out
if errorlevel 1 goto :done

rem ######################################

echo testing arrays and flow of control
..\mawk -f wfrq0.awk %dat% > temp$$
%CMP% temp$$ wfrq-awk.out
if errorlevel 1 goto :done

rem ################################

echo testing function calls and general stress test
..\mawk -f ../examples/decl.awk %dat% > temp$$
%CMP% temp$$ decl-awk.out
if errorlevel 1 goto :done

echo if %CMP% always encountered "no differences", then the tested mawk seems OK
:done
del temp$$
set dat=
