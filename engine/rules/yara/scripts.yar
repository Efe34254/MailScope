rule Script_PowerShell_Encoded_Command {
  meta: severity="high" category="script" description="PowerShell encoded command execution"
  strings: $ps="powershell" nocase $enc1="-encodedcommand" nocase $enc2="-enc" nocase
  condition: $ps and any of ($enc*)
}

rule Script_PowerShell_Download_Execute {
  meta: severity="high" category="script" description="PowerShell download and execution chain"
  strings: $ps="powershell" nocase $download1="DownloadString" nocase $download2="Invoke-WebRequest" nocase $exec1="Invoke-Expression" nocase $exec2="IEX" nocase
  condition: $ps and any of ($download*) and any of ($exec*)
}

rule Script_Base64_Decode_Execute {
  meta: severity="medium" category="script" description="Base64 decoding combined with dynamic execution"
  strings: $decode="FromBase64String" nocase $exec1="Invoke-Expression" nocase $exec2="Reflection.Assembly" nocase
  condition: $decode and any of ($exec*)
}

rule Script_Certutil_Download {
  meta: severity="high" category="lolbin" description="Certutil used as a downloader"
  strings: $tool="certutil" nocase $url="urlcache" nocase $split="-split" nocase
  condition: $tool and ($url or $split)
}

rule Script_MSHTA_Remote_Content {
  meta: severity="high" category="lolbin" description="MSHTA remote content execution"
  strings: $tool="mshta" nocase $http1="http://" nocase $http2="https://" nocase
  condition: $tool and any of ($http*)
}
