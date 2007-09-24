set BINDIST=..\rampartc-bin-1.0.0-win32
if exist %BINDIST% rd /s /q %BINDIST%
mkdir %BINDIST%
mkdir %BINDIST%\samples
mkdir %BINDIST%\modules
mkdir %BINDIST%\include
mkdir %BINDIST%\docs


xcopy /E /I /Y .\bin\samples\*.* %BINDIST%\samples\
xcopy /E /I /Y .\modules\*.* %BINDIST%\modules\
xcopy /E /I /Y .\include\*.* %BINDIST%\include\
xcopy /E /I /Y .\docs\*.* %BINDIST%\docs\

xcopy README %BINDIST%
xcopy INSTALL %BINDIST%
xcopy AUTHORS %BINDIST%
xcopy COPYING %BINDIST%
xcopy LICENSE %BINDIST%
xcopy NEWS %BINDIST%
xcopy NOTICE %BINDIST%
xcopy deploy_rampart.bat %BINDIST%
