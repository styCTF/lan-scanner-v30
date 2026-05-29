Set WshShell = CreateObject("WScript.Shell")
scriptDir = WshShell.CurrentDirectory
Set fso = CreateObject("Scripting.FileSystemObject")
scriptPath = fso.GetParentFolderName(WScript.ScriptFullName)

' 先尝试 pythonw (无控制台窗口)
On Error Resume Next
WshShell.Run "pythonw """ & scriptPath & "\lan_scanner.py""", 0, False
If Err.Number = 0 Then WScript.Quit 0

' 回退到 python
Err.Clear
WshShell.Run "python """ & scriptPath & "\lan_scanner.py""", 0, False
If Err.Number = 0 Then WScript.Quit 0

' 都没找到，弹窗提示
MsgBox "未找到 Python，请确认已安装 Python 3 并添加到 PATH。" & vbCrLf & vbCrLf & "下载地址: https://www.python.org/downloads/", 48, "局域网扫描器 V30"
