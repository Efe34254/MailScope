rule HTML_Credential_Harvest_Form {
  meta: severity="medium" category="html" description="HTML password form posts to an absolute remote URL"
  strings: $html="<html" nocase $password="type=\"password\"" nocase $action1="action=\"http://" nocase $action2="action=\"https://" nocase
  condition: $html and $password and any of ($action*)
}

rule Script_Dynamic_Execution_Primitives {
  meta: severity="medium" category="script" description="Dynamic script execution primitives"
  strings: $eval="eval(" nocase $exec="exec(" nocase $fromchar="String.fromCharCode" nocase $unescape="unescape(" nocase
  condition: 3 of them
}
