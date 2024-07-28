set JADE_HOME=../../../../..
set JADE_LIB_DIR=%JADE_HOME%/lib
set LIB=%JADE_HOME%/add-ons/security/lib
set MYCLPATH=%JADE_LIB_DIR%\jade.jar;%JADE_LIB_DIR%\commons-codec\commons-codec-1.3.jar;%LIB%\jadeSecurity.jar;%LIB%\examples.jar;


java -cp %MYCLPATH% jade.Boot -conf main.conf

pause



