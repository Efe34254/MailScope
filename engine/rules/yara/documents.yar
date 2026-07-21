rule Office_AutoExec_With_Object_Creation {
  meta: severity="high" category="office" description="Office auto-execution macro with object creation"
  strings: $auto1="AutoOpen" nocase $auto2="Document_Open" nocase $auto3="Workbook_Open" nocase $object="CreateObject" nocase
  condition: any of ($auto*) and $object
}

rule Office_Process_Execution_Macro {
  meta: severity="high" category="office" description="Office macro process execution behavior"
  strings: $shell1="WScript.Shell" nocase $shell2="Shell(" nocase $run=".Run" nocase
  condition: 2 of them
}

rule PDF_JavaScript_Action {
  meta: severity="medium" category="pdf" description="PDF contains a JavaScript action"
  strings: $pdf="%PDF-" $js1="/JavaScript" $js2="/JS"
  condition: $pdf at 0 and any of ($js*)
}

rule PDF_Launch_Action {
  meta: severity="high" category="pdf" description="PDF contains an external launch action"
  strings: $pdf="%PDF-" $launch="/Launch"
  condition: $pdf at 0 and $launch
}

rule PDF_Embedded_File_Action {
  meta: severity="medium" category="pdf" description="PDF contains an embedded file object"
  strings: $pdf="%PDF-" $embedded1="/EmbeddedFile" $embedded2="/EmbeddedFiles"
  condition: $pdf at 0 and any of ($embedded*)
}
