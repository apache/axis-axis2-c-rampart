@echo off
SET scn=scenario5
IF [NOT] [%*]==[/?] SET [%scn%]=%*

echo Deploying %scn%
copy  %scn%\client-policy.xml %AXIS2C_HOME%\client_repo\policy.xml
echo Please change path name settings in following files before running the client
echo   1. %AXIS2C_HOME%\client_repo\policy.xml
echo   2. %AXIS2C_HOME%\services\sec_echo\services.xml
pause
@echo on