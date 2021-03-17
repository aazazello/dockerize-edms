<SCRIPT LANGUAGE="VBScript" RUNAT=Server>
Function ConfigGetRuntimeVariable(key)

If key = "EDMS_MOBILE_USER" Then
	ConfigGetRuntimeVariable = "local\mobile"
ElseIf key = "EDMS_DB_HOST" Then
	ConfigGetRuntimeVariable = "172.27.80.1"
ElseIf key = "EDMS_DB_NAME" Then
	ConfigGetRuntimeVariable = "paydox-epd-2-14"
ElseIf key = "EDMS_DB_USER" Then
	ConfigGetRuntimeVariable = "paydox-sys"
ElseIf key = "EDMS_DB_PASS" Then
	ConfigGetRuntimeVariable = "!QAZ1qaz"
ElseIf key = "EDMS_LANG" Then
	ConfigGetRuntimeVariable = "RUS"
ElseIf key = "EDMS_COLOR_SCHEME" Then
	ConfigGetRuntimeVariable = "1"
ElseIf key = "EDMS_SMTP_HOST" Then
	ConfigGetRuntimeVariable = "stone-m2.local"
ElseIf key = "EDMS_SMTP_AUTH_TYPE" Then
	ConfigGetRuntimeVariable = "OFF"
ElseIf key = "EDMS_SMTP_USER" Then
	ConfigGetRuntimeVariable = ""
ElseIf key = "EDMS_SMTP_PASS" Then
	ConfigGetRuntimeVariable = ""
Else
	ConfigGetRuntimeVariable = ""
End If

End Function
</SCRIPT>