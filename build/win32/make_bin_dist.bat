set BINDIST=..\rampartc-bin-1.2.0-win32
if exist %BINDIST% rd /s /q %BINDIST%
mkdir %BINDIST%
mkdir %BINDIST%\bin
mkdir %BINDIST%\bin\samples
mkdir %BINDIST%\modules
mkdir %BINDIST%\include
mkdir %BINDIST%\include\rampart-1.2.0
mkdir %BINDIST%\docs


xcopy /E /I /Y .\bin\samples\*.* %BINDIST%\bin\samples\
xcopy /E /I /Y .\modules\*.* %BINDIST%\modules\
xcopy /E /I /Y .\include\*.* %BINDIST%\include\rampart-1.2.0\
xcopy /E /I /Y .\docs\*.* %BINDIST%\docs\

xcopy README %BINDIST%
xcopy INSTALL %BINDIST%
xcopy AUTHORS %BINDIST%
xcopy COPYING %BINDIST%
xcopy LICENSE %BINDIST%
xcopy NEWS %BINDIST%
xcopy NOTICE %BINDIST%
xcopy deploy_rampart.bat %BINDIST%
