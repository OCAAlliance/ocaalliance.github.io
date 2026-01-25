prompt -- 
rem anmake <srcfile> 
rem Writes Index.html
rem Uses Python program 'pyexpander'.  

set ANroot=C:\Users\veeze\Data\Projects\Pro\54 Networking Stds\OCA\! Marketing\Blog
set expand=C:\Program Files (JB)\! Programming\pyexpander\expander.exe
set macfile="%ANroot%\macros\ANmacros.txt"

cd %~p1

del ###in
type %macfile% >###in
type %1 >>###in

echo Input=%macfile%+%1

del Index.html /Q
"%expand%" -a ###in >Index.html

pause