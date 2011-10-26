echo off
rem  tests if mawk has been compiled to correctly handle
rem  floating point exceptions

echo testing division by zero
type fpetest1.awk
..\mawk -f fpetest1.awk
if errorlevel 128 goto :test1_128
if errorlevel 3 goto :test1_3
if errorlevel 2 goto :test1_2
if errorlevel 1 goto :test1_1
set ret1=0
goto :test2
:test1_128
set ret1=128
goto :test2
:test1_3
set ret1=3
goto :test2
:test1_2
set ret1=2
goto :test2
:test1_1
set ret1=1

:test2
echo testing overflow
type fpetest2.awk
..\mawk -f fpetest2.awk
if errorlevel 128 goto :test2_128
if errorlevel 3 goto :test2_3
if errorlevel 2 goto :test2_2
if errorlevel 1 goto :test2_1
set ret2=0
goto :test3
:test2_128
set ret2=128
goto :test3
:test2_3
set ret2=3
goto :test3
:test2_2
set ret2=2
goto :test3
:test2_1
set ret2=1

:test3
echo testing domain error
type fpetest3.awk
..\mawk -f fpetest3.awk > temp$$
if errorlevel 128 goto :test3_128
if errorlevel 3 goto :test3_3
if errorlevel 2 goto :test3_2
if errorlevel 1 goto :test3_1
set ret3=0
goto :type3
:test3_128
set ret3=128
goto :type3
:test3_3
set ret3=3
goto :type3
:test3_2
set ret3=2
goto :type3
:test3_1
set ret3=1

:type3
type temp$$

rem  the returns should all be zero or all 2

echo *************************************
echo return1 = %ret1%
echo return2 = %ret2%
echo return3 = %ret3%

set exception=0
if %ret1% == 2 goto :okay1
if %ret1% == 0 goto :okay1
echo test1 failed
set exception=1
:okay1
if %ret2% == 2 goto :okay2
if %ret2% == 0 goto :okay2
echo test2 failed
set exception=1
:okay2
if %ret3% == 2 goto :okay3
if %ret3% == 0 goto :okay3
echo test3 failed
set exception=1
:okay3

if %exception% == 1 goto :done

set same=1
if %ret1% == %ret2% goto :same12
set same=0
:same12
if %ret2% == %ret3% goto :same23
set same=0
:same23

if %same% == 1 goto :same123
echo results are not consistent
echo return values should all be 0 if ignoring FPEs (e.g. with IEEE754)
echo or all 2 if trapping FPEs
goto :cleanup

:same123
if %ret1% == 0 goto :allzero
echo results consistent: trapping floating exceptions
goto :cleanup

:allzero
echo results consistent: ignoring floating exceptions
grep -i nan temp$$ >NUL
if not errorlevel 1 goto :cleanup
echo but the library is not IEEE754 compatible
echo test 3 failed

:cleanup
del temp$$

:done
set ret1=
set ret2=
set ret3=
set same=
if %exception% == 1 goto :done1
set exception=
exit 0
:done1
set exception=
exit 1
exit %exception%
