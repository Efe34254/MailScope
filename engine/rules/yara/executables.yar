rule PE_Process_Injection_APIs {
  meta: severity="high" category="pe" description="PE imports a process injection API combination"
  strings: $mz="MZ" $a="VirtualAllocEx" ascii wide $b="WriteProcessMemory" ascii wide $c="CreateRemoteThread" ascii wide
  condition: $mz at 0 and 2 of ($a,$b,$c)
}

rule PE_Credential_Dumping_Indicators {
  meta: severity="high" category="credential_access" description="Credential dumping indicators"
  strings: $mz="MZ" $lsass="lsass" nocase ascii wide $dump="MiniDumpWriteDump" ascii wide
  condition: $mz at 0 and $lsass and $dump
}

rule PE_Windows_Downloader_APIs {
  meta: severity="medium" category="network" description="Windows downloader API imports"
  strings: $mz="MZ" $a="URLDownloadToFile" ascii wide $b="InternetOpenUrl" ascii wide $c="WinHttpOpen" ascii wide
  condition: $mz at 0 and 2 of ($a,$b,$c)
}

rule PE_Run_Key_Persistence {
  meta: severity="medium" category="persistence" description="Windows Run key persistence strings"
  strings: $mz="MZ" $run1="Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide $reg="RegSetValueEx" ascii wide
  condition: $mz at 0 and $run1 and $reg
}

rule PE_Suspicious_Command_Interpreter_Chain {
  meta: severity="medium" category="execution" description="PE references multiple command interpreters"
  strings: $mz="MZ" $cmd="cmd.exe" nocase ascii wide $ps="powershell.exe" nocase ascii wide $wscript="wscript.exe" nocase ascii wide
  condition: $mz at 0 and 2 of ($cmd,$ps,$wscript)
}
