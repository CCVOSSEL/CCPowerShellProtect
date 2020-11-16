# CCPowerShellProtect www.ccvossel.de

## Motivation
Die in allen Windows-Systemen vorinstallierte mächtige PowerShell steht grundsätzlich als sinnvolles Hilfsmittel für Administratoren oder zur Automatisierung zur Verfügung. Durch die vielen Anwendungsmöglichkeiten haben auch Hacker die PowerShell als Angriffsvektor entdeckt und machen in den letzten Jahren sehr starken Gebrauch von ihr.
Zusätzlich kommen verschiedene PowerShell-basierende Frameworks (z.B. „Nishang“, „PowerSploit“ oder „PowerShell Empire“) zum Einsatz, die auch technisch nicht versierte Angreifer in die Lage versetzen PowerShell-Schadcode zu entwickeln und einzusetzen.

Um derartige Angriffe zu erkennen, sollten PowerShell-Aktivitäten aller Windows-Systeme (Clients und Server) zentral protokolliert und überwacht werden. Dadurch wird es möglich die Ausführung schädlicher Kommandos zu erkennen und die Ausbreitung von Schadsoftware im Unternehmen einzudämmen bzw. infizierte Rechner zu isolieren. Ebenfalls erforderlich sind diese Daten für die forensische Analyse nach einem Angriff.

Angriffe auf vollständige Infrastrukturen erfolgen oft Schritt für Schritt, wobei anfangs nur wenige Systeme kompromittiert werden. Die weiteren Schritte werden dann meistens über ferngesteuerte Anweisungen des Angreifers durchgeführt, um viele andere, meist kritischere Systeme zu kompromittieren. Diese sogenannte „Lateral Movement“ benötigt in der Regel viel Zeit, so dass sich die Angreifer für Tage oder sogar Wochen im Netzwerk bewegen, um an ihr Ziel zu gelangen. Durch die Überwachung aller PowerShell-Aktivitäten besteht eine große Chance diese Angriffe zu Erkennen und rechtzeitig Gegenmaßnahmen einzuleiten. 

Auch das Bundesamt für Sicherheit in der Informationstechnik (BSI) empfiehlt diese Maßnahme in seinem IT-Grundschutz (SYS.2.2.3.A22): 
„Die PowerShell-Ausführung selbst SOLLTE zentral protokolliert und die Protokolle überwacht werden.“
Zur Umsetzung dieser Anforderung haben unsere Recherchen keine einfache, kostengünstige Lösung auf dem Markt gefunden. Daher haben wir beschlossen unsere eigene, schlanke, aber effektive Lösung für das PowerShell-Monitoring zu entwickeln.

Wie die CCVOSSEL GmbH das PowerShell-Monitoring umgesetzt hat, die dabei entstandene FOSS-Lösung (Free and Open Source Software) „CCPowerShellProtect“ funktioniert und zu verwenden ist, wird in einem Whitepaper beschrieben. Dieses finden Sie unter der URL: https://www.ccvossel.de.

