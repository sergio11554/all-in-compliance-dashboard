from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


OUT = Path(__file__).with_name("SFM_Compliance_Detailierter_30_Minuten_Vortragsleitfaden.docx")

DARK = "0B1F3A"
BLUE = "2E74B5"
TEAL = "007C89"
MUTED = "4A5D70"
LIGHT_BLUE = "E8F4F8"
LIGHT_GRAY = "F4F7FA"
LIGHT_TEAL = "EEF9FA"
LIGHT_AMBER = "FFF6E6"
BORDER = "C9D6E2"


def twips(inches):
    return str(int(inches * 1440))


def shade(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def border(cell, color=BORDER, size="8"):
    tc_pr = cell._tc.get_or_add_tcPr()
    borders = tc_pr.first_child_found_in("w:tcBorders")
    if borders is None:
        borders = OxmlElement("w:tcBorders")
        tc_pr.append(borders)
    for edge in ("top", "left", "bottom", "right"):
        element = borders.find(qn(f"w:{edge}"))
        if element is None:
            element = OxmlElement(f"w:{edge}")
            borders.append(element)
        element.set(qn("w:val"), "single")
        element.set(qn("w:sz"), size)
        element.set(qn("w:space"), "0")
        element.set(qn("w:color"), color)


def fixed_table(table, widths):
    table.autofit = False
    tbl = table._tbl
    old_grid = tbl.tblGrid
    if old_grid is not None:
        tbl.remove(old_grid)
    grid = OxmlElement("w:tblGrid")
    for width in widths:
        col = OxmlElement("w:gridCol")
        col.set(qn("w:w"), twips(width))
        grid.append(col)
    tbl.insert(0, grid)
    for row in table.rows:
        keep_row(row)
        for idx, width in enumerate(widths):
            cell = row.cells[idx]
            cell.width = Inches(width)
            tc_pr = cell._tc.get_or_add_tcPr()
            tc_w = tc_pr.find(qn("w:tcW"))
            if tc_w is None:
                tc_w = OxmlElement("w:tcW")
                tc_pr.append(tc_w)
            tc_w.set(qn("w:type"), "dxa")
            tc_w.set(qn("w:w"), twips(width))


def keep_row(row):
    tr_pr = row._tr.get_or_add_trPr()
    if tr_pr.find(qn("w:cantSplit")) is None:
        tr_pr.append(OxmlElement("w:cantSplit"))


def cell_text(cell, text, bold=False, color=DARK, size=9.3):
    cell.text = ""
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    run = p.add_run(text)
    run.font.name = "Calibri"
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor.from_string(color)


def para(doc, text="", size=10.2, color=MUTED, bold=False, after=6, before=0, align=None):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(before)
    p.paragraph_format.space_after = Pt(after)
    if align is not None:
        p.alignment = align
    run = p.add_run(text)
    run.font.name = "Calibri"
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor.from_string(color)
    return p


def bullet(doc, text, level=0, bold_prefix=None):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.22 + level * 0.18)
    p.paragraph_format.first_line_indent = Inches(-0.12)
    p.paragraph_format.space_after = Pt(3)
    r = p.add_run("• ")
    r.font.name = "Calibri"
    r.font.size = Pt(9.8)
    r.font.color.rgb = RGBColor.from_string(TEAL)
    if bold_prefix and text.startswith(bold_prefix):
        r = p.add_run(bold_prefix)
        r.font.name = "Calibri"
        r.font.size = Pt(9.8)
        r.font.bold = True
        r.font.color.rgb = RGBColor.from_string(DARK)
        rest = text[len(bold_prefix):]
        r = p.add_run(rest)
    else:
        r = p.add_run(text)
    r.font.name = "Calibri"
    r.font.size = Pt(9.8)
    r.font.color.rgb = RGBColor.from_string(DARK)


def heading(doc, text, level=1, before=14, after=7):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(before)
    p.paragraph_format.space_after = Pt(after)
    run = p.add_run(text)
    run.font.name = "Calibri"
    run.font.bold = True
    run.font.color.rgb = RGBColor.from_string(BLUE if level <= 2 else "1F4D78")
    run.font.size = Pt(17 if level == 1 else 13.5 if level == 2 else 11.5)
    return p


def callout(doc, title, body, fill=LIGHT_BLUE):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    fixed_table(table, [6.6])
    cell = table.rows[0].cells[0]
    shade(cell, fill)
    border(cell, "A7C9D8", "10")
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(3)
    r = p.add_run(title)
    r.font.name = "Calibri"
    r.font.size = Pt(10)
    r.font.bold = True
    r.font.color.rgb = RGBColor.from_string(TEAL)
    p = cell.add_paragraph()
    p.paragraph_format.space_after = Pt(0)
    r = p.add_run(body)
    r.font.name = "Calibri"
    r.font.size = Pt(9.6)
    r.font.color.rgb = RGBColor.from_string(DARK)


def add_header_footer(doc):
    section = doc.sections[0]
    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    header.text = ""
    r = header.add_run("SFM Compliance | 30-Minuten-Vortragsleitfaden")
    r.font.name = "Calibri"
    r.font.size = Pt(8)
    r.font.color.rgb = RGBColor.from_string("6B7C8F")

    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.text = ""
    r = footer.add_run("Die Plattform unterstützt Vorbereitung und Prüfung; fachliche Freigabe bleibt beim Berater/Admin.")
    r.font.name = "Calibri"
    r.font.size = Pt(8)
    r.font.color.rgb = RGBColor.from_string("6B7C8F")


def add_cover(doc):
    para(doc, "SFM Compliance", size=25, color=DARK, bold=True, after=3)
    para(doc, "Detailierter 30-Minuten-Vortragsleitfaden", size=15, color=MUTED, after=14)

    meta = doc.add_table(rows=1, cols=3)
    meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    fixed_table(meta, [2.2, 2.2, 2.2])
    for cell, text in zip(
        meta.rows[0].cells,
        ["Format\nLive-Demo + Gesprächsleitfaden", "Stand\n16.06.2026", "Zielgruppe\nKollegen, Kunden, Berater"],
    ):
        shade(cell, LIGHT_GRAY)
        border(cell)
        cell_text(cell, text, size=9.4)

    doc.add_paragraph()
    callout(
        doc,
        "Wichtiges Produktprinzip",
        "Die Plattform ersetzt nicht den Berater. Sie führt Kunden durch Vorbereitung, Datenerfassung, Nachweise und formale Lücken. Fachliche Bewertung, Freigabe, Ablehnung, Audit-Relevanz und Auditbereitschaft bleiben beim Berater/Admin.",
    )
    callout(
        doc,
        "Sprechweise im Vortrag",
        "Nicht sagen: Die Plattform macht euch ISO-konform oder NIS-2-erfüllt. Besser sagen: Die Plattform sammelt strukturiert Informationen, zeigt offene Punkte und bereitet die Beraterprüfung nachvollziehbar vor.",
        fill=LIGHT_AMBER,
    )


def add_agenda(doc):
    heading(doc, "1. 30-Minuten-Ablauf", 1)
    para(
        doc,
        "Der Ablauf ist so aufgebaut, dass zuerst der Nutzen für Kunden sichtbar wird und danach die fachliche Steuerung durch Berater/Admin gezeigt wird.",
    )
    table = doc.add_table(rows=1, cols=4)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    widths = [0.9, 1.55, 2.95, 1.2]
    fixed_table(table, widths)
    for cell, text in zip(table.rows[0].cells, ["Minute", "Station", "Was erklären?", "Route"]):
        shade(cell, "E8EEF5")
        border(cell)
        cell_text(cell, text, bold=True, size=9.3)
    rows = [
        ("0-3", "Einordnung", "Kernaussage, Rollenlogik und Grenze: Vorbereitung ja, fachliche Freigabe durch Berater/Admin.", "Start"),
        ("3-7", "Dashboard", "Management-Übersicht, Tool-Hub, heutige Aufgaben, Risiken, Nachweise und Auditpaket-Status.", "#dashboard"),
        ("7-11", "Kundenmodus", "Geführte Strecke: Startprofil, Assets, Risiken, Policies, Nachweise, SoA, Abgabecheck.", "#guided"),
        ("11-15", "Projektplan", "Chronologische Arbeitspakete, Owner, Termine, Status, ISO/NIS-2-Trennung und Dokumentlinks.", "#project"),
        ("15-21", "Compliance", "ISO 27001, NIS-2, Dokumentation, Review Center, Auditmatrix, SoA und Templates.", "#iso/#review"),
        ("21-25", "Register", "Assets, Risiken, Rechtsregister und Lieferanten als gemeinsame Datenbasis.", "#assets"),
        ("25-28", "Betrieb", "Policies, Incidents, Contracts, Integrationen und Aufgaben im Alltag.", "#policies"),
        ("28-30", "Abschluss", "Administration, Audit Trail, Team-Einladungen, Produktionsreife und nächster Ausbau.", "#team"),
    ]
    for values in rows:
        row = table.add_row()
        keep_row(row)
        for cell, text in zip(row.cells, values):
            border(cell)
            cell_text(cell, text, size=9)
    doc.add_paragraph()


def module_block(doc, title, timebox, route, purpose, functions, demo, talk, notes=None, page_break_before=False):
    title_paragraph = heading(doc, title, 2, before=10, after=4)
    if page_break_before:
        title_paragraph.paragraph_format.page_break_before = True
    table = doc.add_table(rows=1, cols=3)
    fixed_table(table, [1.4, 2.55, 2.55])
    for cell, text in zip(table.rows[0].cells, [f"Zeit\n{timebox}", f"Route\n{route}", "Kurzversprechen"]):
        shade(cell, LIGHT_GRAY)
        border(cell)
        cell_text(cell, text, bold=False, size=8.8)
    row = table.add_row()
    for cell, text in zip(row.cells, ["", "", purpose]):
        border(cell)
        cell_text(cell, text, size=9)
    doc.add_paragraph()

    para(doc, "Eingebaute Funktionen", size=10.4, color=DARK, bold=True, after=3)
    for item in functions:
        bullet(doc, item)
    para(doc, "Was in der Demo zeigen", size=10.4, color=DARK, bold=True, after=3, before=3)
    for item in demo:
        bullet(doc, item)
    callout(doc, "Möglicher Sprechtext", talk, fill=LIGHT_TEAL)
    if notes:
        para(doc, "Wichtige Einordnung", size=10.4, color=DARK, bold=True, after=3)
        for item in notes:
            bullet(doc, item)


def add_overview_modules(doc):
    heading(doc, "2. Überblick: Start, Steuerung und Kundenführung", 1)
    module_block(
        doc,
        "2.1 Dashboard",
        "4 Minuten",
        "/#dashboard",
        "Das Dashboard ist der Management-Einstieg. Es zeigt nicht jedes Detail, sondern die wichtigsten nächsten Handlungen und Blocker.",
        [
            "Aktives Kundenprojekt mit Projektstatus, offenen Aufgaben, Nachweisen und offenen Policies.",
            "Tool-Hub mit zentralen Einstiegskacheln: Heute erledigen, Beraterprüfung, Nachweise prüfen, Risiken bearbeiten, NIS-2 Navigator und Auditpaket.",
            "Management-/Compliance-Übersicht mit Top-Risiken, Audit-Blockern, formalen Spuren und vorbereitendem Status.",
            "Klare Trennung zwischen automatischer Vollständigkeitslogik und Beraterfreigabe.",
            "Schnellbuttons zu Kundenmodus, Projektplan, Nachweisen und Policies.",
        ],
        [
            "Startseite öffnen und zuerst die Kacheln erklären.",
            "Auf eine Kachel wie 'Heute erledigen' oder 'Beraterprüfung' zeigen.",
            "Betonen, dass die Prozentwerte nur Arbeitsstand/Formalstatus sind, nicht ISO-Konformität.",
        ],
        "Hier bekommt man in wenigen Sekunden ein Gefühl dafür, wo das Projekt steht: Was ist offen, was wartet auf Prüfung, wo fehlen Nachweise und was blockiert ein späteres Auditpaket. Das ersetzt keine Fachbewertung, aber es verhindert, dass Aufgaben und Nachweise im Projekt verstreut bleiben.",
    )
    module_block(
        doc,
        "2.2 Benachrichtigungen",
        "2 Minuten",
        "/#notifications",
        "Benachrichtigungen bündeln Rückfragen, Fristen, Nacharbeit und Statusänderungen.",
        [
            "Inbox für neue Einreichungen und Änderungen.",
            "Hinweise für Nacharbeit, Fristen, Rückfragen und Freigaben.",
            "Trennung nach Priorität und Status, damit Kunden nicht suchen müssen.",
            "Kann als Kommunikationsbrücke zwischen Kundenmodus und Beraterprüfung genutzt werden.",
        ],
        [
            "Eine Rückgabe oder offene Aufgabe zeigen.",
            "Erklären, dass Benachrichtigungen den Kunden zurück in den richtigen Arbeitsbereich führen.",
        ],
        "Die Idee ist: Der Kunde muss nicht wissen, ob etwas im Risiko-, Dokumentations- oder Policy-Modul liegt. Er bekommt eine verständliche Meldung und landet dort, wo er weiterarbeiten soll.",
    )
    module_block(
        doc,
        "2.3 Kundenmodus",
        "5 Minuten",
        "/#guided",
        "Der Kundenmodus übersetzt die Plattform in einfache nächste Schritte und reduziert Fachsprache.",
        [
            "Geführte Route: Startprofil -> Assets -> Risiken -> Policies -> Nachweise -> SoA -> Abgabecheck -> Einreichen.",
            "Heute-erledigen-Ansicht mit den wichtigsten Aufgaben.",
            "Nacharbeits-Zentrale für vom Berater zurückgegebene Punkte.",
            "Statusleiste mit verständlichen Zuständen: eingereicht, wartet auf Prüfung, Nacharbeit nötig, freigegeben.",
            "Modul-Kompass: erklärt, welches Thema wohin gehört.",
            "Abgabe-Check: zeigt formal, was vor Einreichung noch fehlt.",
            "Prüfablauf-Timeline: Einreichen -> Berater prüft -> Rückfrage -> Freigabe.",
        ],
        [
            "Vom Kundenmodus aus eine Aufgabe öffnen.",
            "Eine Nacharbeit zeigen und erklären, was der Kunde konkret ergänzt.",
            "Abgabe-Check zeigen und klar sagen: 'zur Prüfung bereit' ist nicht 'auditbereit'.",
        ],
        "Das ist die Kundensicht. Der Kunde soll nicht durch ISO-Fachsprache navigieren müssen, sondern sieht: Was muss ich jetzt ausfüllen? Was habe ich eingereicht? Was wartet auf Prüfung? Was muss ich nacharbeiten?",
        [
            "Kunden dürfen einreichen und bearbeiten, aber nicht final freigeben.",
            "Fachliche Entscheidung bleibt im Review Center bei Berater/Admin.",
        ],
    )
    module_block(
        doc,
        "2.4 Projektstrukturplan",
        "4 Minuten",
        "/#project",
        "Der Projektstrukturplan macht aus ISO 27001 und NIS-2 einen chronologischen Arbeitsplan.",
        [
            "Getrennte Spuren für ISO 27001 und NIS-2.",
            "Arbeitspakete mit Owner, Status, Termin, Priorität und Fortschritt.",
            "Verknüpfung zu benötigten Policies, Templates, Nachweisen und Registern.",
            "Import-Logik für vorhandene Projektpläne/Excel-Tabellen ist vorbereitet.",
            "Einseiten-Board für schnelle Übersicht und Phasenlogik für detaillierte Steuerung.",
        ],
        [
            "Projektplan öffnen, ISO/NIS-2-Trennung zeigen.",
            "Ein Arbeitspaket anklicken und die verknüpften Dokumente/Nachweise erklären.",
            "Owner und Status als Kundensteuerung zeigen.",
        ],
        "Der Projektplan beantwortet die Frage: Was passiert von jetzt bis zur Abgabe? Er verbindet Aufgaben, Dokumentation und Nachweise, statt nur eine lose To-do-Liste zu sein.",
    )


def add_compliance_modules(doc):
    doc.add_page_break()
    heading(doc, "3. Compliance-Bereich: Anforderungen, Nachweise und Prüfung", 1)
    module_block(
        doc,
        "3.1 ISO 27001",
        "3 Minuten",
        "/#iso",
        "ISO 27001 wird als eigene fachliche Sicht geführt und nicht mit NIS-2 vermischt.",
        [
            "Clause-/Annex-A-orientierte Übersicht.",
            "Arbeitsartefakte pro Anforderung: was muss vorbereitet oder nachgewiesen werden.",
            "Verknüpfte Nachweise und Registereinträge.",
            "Hilfetexte in Kundensprache, aber ISO-Abschnitte fachlich sauber benannt.",
            "Statuslogik für Umsetzung, Nachweis und Beraterprüfung.",
        ],
        [
            "Clause oder Annex-A-Control auswählen.",
            "Arbeitsartefakte und verknüpfte Nachweise zeigen.",
            "Erklären, dass die Plattform vorbereitet, die Bewertung aber fachlich erfolgt.",
        ],
        "Hier geht es um die ISO-Sicht: Anforderungen, Controls, Artefakte und Nachweise. Wichtig ist: Wir zeigen strukturiert, was vorbereitet ist und was fehlt. Wir behaupten nicht automatisch, dass etwas ISO-konform ist.",
    )
    module_block(
        doc,
        "3.2 NIS-2",
        "3 Minuten",
        "/#nis2",
        "NIS-2 wird separat geführt, damit regulatorische Einordnung nicht in ISO 27001 untergeht.",
        [
            "Eigene NIS-2-Arbeitsbereiche, etwa Betroffenheit, Pflichten, Nachweise und offene Punkte.",
            "Rechtsregister-, Auditmatrix- und Projektplan-Sichten.",
            "Klare Abgrenzung: ISO 27001 ersetzt NIS-2 nicht automatisch.",
            "Überschneidungen werden als gemeinsame Arbeitspakete sichtbar, bleiben aber fachlich getrennt.",
        ],
        [
            "NIS-2-Bereich öffnen und die getrennte Sicht erklären.",
            "Auf offene Pflichten/Nachweise zeigen.",
            "Betonen, dass finale NIS-2-Einordnung beim Berater/Admin bleibt.",
        ],
        "Der Nutzen ist, dass Kunden nicht zwei parallele Welten pflegen müssen. Gemeinsame Daten werden genutzt, aber die Bewertung bleibt getrennt: ISO ist ISO, NIS-2 ist NIS-2.",
    )
    module_block(
        doc,
        "3.3 Dokumentation und Nachweise",
        "4 Minuten",
        "/#documents",
        "Das Dokumentationsmodul ist das Nachweis-Center der Plattform.",
        [
            "Upload oder manuelle Anlage von Nachweisen mit Metadaten.",
            "Zuordnung zu ISO, NIS-2, SoA, Risiken, Lieferanten, Policies oder Aufgaben.",
            "Nachweis-Gap-Scanner: zeigt formal fehlende oder ungeprüfte Nachweise.",
            "Review-Queue: eingereichte Dokumente können an Beraterprüfung übergeben werden.",
            "Versionierung: ältere Versionen bleiben nachvollziehbar.",
            "SOC-/SIEM-Report-Bereich zur strukturierten Ablage von Security-Reports.",
        ],
        [
            "Nachweis anlegen oder vorhandenen Eintrag öffnen.",
            "Metadaten, Zuordnung und Prüfstatus zeigen.",
            "Formale Lücke erklären: 'Nachweis fehlt' oder 'zur Prüfung bereit', nicht 'erfüllt'.",
        ],
        "Das Nachweis-Center ist wichtig, weil Audits und Reviews selten an fehlender Absicht scheitern, sondern an fehlenden, ungeordneten oder nicht nachvollziehbaren Nachweisen.",
        page_break_before=True,
    )
    module_block(
        doc,
        "3.4 Beraterprüfung / Review Center",
        "5 Minuten",
        "/#review",
        "Das Review Center ist die Kontrollinstanz für Berater/Admin.",
        [
            "Zentrale Übersicht über neue Einreichungen, in Beraterprüfung, Nacharbeit, Freigaben und Audit-Blocker.",
            "Review-Liste für Nachweise, Risiken, SoA-Einträge, Policies, Assets, Aufgaben und auditpaket-relevante Punkte.",
            "Detailpanel mit Kundeneingabe, verknüpftem Nachweis, ISO-/NIS-2-Zuordnung und Kommentaren.",
            "Zwei Kommentararten: interner Beraterkommentar und Kommentar an Kunde.",
            "Entscheidungen: freigeben, Nacharbeit nötig, ablehnen, später prüfen, auditrelevant markieren.",
            "Bei Nacharbeit wird automatisch eine Kundenaufgabe erzeugt.",
        ],
        [
            "Eine Review-Zeile öffnen.",
            "Interne Notiz und Kundenkommentar erklären.",
            "Nacharbeit anfordern und zeigen, dass daraus eine Kundenaufgabe wird.",
        ],
        "Das ist der wichtigste Punkt für unser Produktprinzip: Die Plattform sammelt und strukturiert. Der Berater entscheidet. Kunden können einreichen, aber nicht final freigeben; Freigaben, Ablehnungen und Audit-Relevanz bleiben beim Berater/Admin.",
    )
    module_block(
        doc,
        "3.5 Auditmatrix und SoA Matrix",
        "4 Minuten",
        "/#audit und /#soa",
        "Auditmatrix und SoA verbinden Anforderungen, Kontrollen, Aufgaben und Nachweise.",
        [
            "Auditmatrix zeigt Anforderungen, Nachweise, Aufgaben und Prüfstatus in einer nachvollziehbaren Sicht.",
            "SoA Matrix bildet Annex-A-Entscheidungen ab: anwendbar, nicht anwendbar, Begründung, Umsetzung, Nachweis.",
            "SoA-Wizard unterstützt beim strukturierten Ausfüllen.",
            "Audit-Gate unterscheidet vorbereitet, in Prüfung, Nacharbeit, freigegeben und exportbereit.",
        ],
        [
            "Eine SoA-Zeile öffnen und Nachweis/Status zeigen.",
            "Auditmatrix als Überblick für Traceability zeigen.",
            "Auditpaket-Hinweis erklären: vorbereitet, aber nicht automatisch auditbereit.",
        ],
        "Diese Sichten sind für Berater und Audits wichtig, weil sie nachvollziehbar machen, warum ein Control wie bewertet wurde und welcher Nachweis dahintersteht.",
    )
    module_block(
        doc,
        "3.6 Templates",
        "3 Minuten",
        "/#templates",
        "Templates sind ausfüllbare Arbeitsvorlagen mit Erklärungen, Beispielen und Dokumentanker.",
        [
            "Template-Bibliothek für Scope, Risiken, SoA, Lieferanten, Policies, Nachweise und weitere ISMS-Artefakte.",
            "Feld-Erklärungen: Geltungsbereich, Kurzbeschreibung, Owner, Review-Datum, Nachweise und Beispiele.",
            "Live-Vorschau für ausfüllbare Vorlagen.",
            "Gespeicherte Entwürfe und Verknüpfung zu Dokumentation/Policy Management.",
        ],
        [
            "Template öffnen und die Erklärtexte zeigen.",
            "Ein Beispiel-Feld ausfüllen.",
            "Erklären, dass Kunden dadurch wissen, was in ein Feld gehört.",
        ],
        "Templates sind der Unterschied zwischen 'Bitte lade eine Policy hoch' und 'Hier ist eine verständliche Vorlage, die du ausfüllen kannst'.",
    )


def add_register_modules(doc):
    doc.add_page_break()
    heading(doc, "4. Register: Gemeinsame Datenbasis", 1)
    module_block(
        doc,
        "4.1 Asset Management",
        "3 Minuten",
        "/#assets",
        "Assets sind die Grundlage für Risiken, Schutzbedarf, Nachweise und Verantwortlichkeiten.",
        [
            "Assets mit Name, Kategorie, Owner, Kritikalität und Bezug zu ISO/NIS-2 erfassen.",
            "Kundensicht mit einfacher Erfassung und klaren nächsten Schritten.",
            "Verknüpfung zu Risiken, Nachweisen und Aufgaben.",
            "Review-Status und Beraterprüfung für eingereichte Asset-Daten.",
        ],
        [
            "Asset anlegen oder vorhandenen Eintrag öffnen.",
            "Owner und Kritikalität zeigen.",
            "Erklären, dass ein Asset später Risiken und Nachweise auslöst.",
        ],
        "Für Kunden ist 'Asset' oft abstrakt. Deshalb erklären wir es praktisch: Welche Systeme, Informationen oder Services sind wichtig und wer ist dafür verantwortlich?",
    )
    module_block(
        doc,
        "4.2 Risiko Management",
        "4 Minuten",
        "/#risks",
        "Risiken werden nicht als trockene Tabelle begonnen, sondern über einfache Fragen.",
        [
            "Risikoworkshop: Was ist wichtig? Was kann schiefgehen? Was macht ihr dagegen? Wer ist verantwortlich?",
            "Risikoregister mit Bewertung, Behandlung, Owner, Status und Nachweisen.",
            "Risikomatrix/Heatmap für schnelle Priorisierung.",
            "SOC-/SIEM-Hinweise können in Risikoideen übersetzt werden.",
            "Kritische Risiken können für Beraterprüfung und Auditpaket markiert werden.",
        ],
        [
            "Ein Risiko erfassen und in Matrix/Register zeigen.",
            "Top-Risiko im Dashboard wiederfinden.",
            "Behandlungsstatus erklären.",
        ],
        "Das Risiko-Modul soll Kunden nicht mit Methodik erschlagen. Es startet mit Alltagssprache und führt dann in ein prüfbares Register.",
    )
    module_block(
        doc,
        "4.3 Rechtsregister",
        "2 Minuten",
        "/#legal",
        "Das Rechtsregister hält regulatorische Themen und Zuständigkeiten strukturiert fest.",
        [
            "Einträge mit Thema, Zuständigkeit, Status, Termin und Nachweis.",
            "NIS-2-relevante Punkte können separat sichtbar gemacht werden.",
            "Verknüpfung zu Aufgaben, Dokumenten und Beraterprüfung.",
        ],
        [
            "Einen Registereintrag öffnen.",
            "Status und Nachweisbezug erklären.",
        ],
        "Hier geht es nicht um automatische Rechtsberatung, sondern um Nachvollziehbarkeit: Welche regulatorischen Themen wurden erkannt, wer kümmert sich darum und welcher Nachweis liegt vor?",
        page_break_before=True,
    )
    module_block(
        doc,
        "4.4 Vendor Management",
        "3 Minuten",
        "/#suppliers",
        "Lieferanten werden mit Kritikalität, Nachweisen, Verträgen und Review verbunden.",
        [
            "Lieferant anlegen mit Leistung, Zuordnung ISO/NIS-2, Kritikalität, Owner und Review-Status.",
            "Einheitlicher Ablauf: Erfassen -> Nachweis -> Beraterprüfung -> Freigabe.",
            "Metriken: Lieferanten, Review offen, mit Nachweis, wartet auf Berater, freigegeben.",
            "Aktionen: Nachweis vorbereiten, Vertrag öffnen/verknüpfen, zur Beraterprüfung geben, Aufgaben erstellen.",
        ],
        [
            "Vendor Management öffnen und den Ablauf zeigen.",
            "Nachweis/Vertrag verknüpfen.",
            "Beraterprüfung erklären.",
        ],
        "Das Lieferantenmodul ist wichtig, weil viele Sicherheitsnachweise nicht intern entstehen, sondern aus Verträgen, AVV, Sicherheitsanlagen oder Dienstleisterinformationen.",
    )


def add_operations_modules(doc):
    doc.add_page_break()
    heading(doc, "5. Betrieb: Alltag, Policies, Vorfälle und Aufgaben", 1)
    module_block(
        doc,
        "5.1 Policy Management",
        "4 Minuten",
        "/#policies",
        "Policy Management verbindet vorbereitete Policy-Pakete mit echten Dokumenten, Review und Versionierung.",
        [
            "Policy-Automation mit ISO-27001-Kern-Policies, NIS-2-Überschneidungen und Annex-A-/ISMS-Verfahren.",
            "Policy Register mit Owner, Version, Status, Review-Datum und Nachweis-/Dokumentanker.",
            "Policy-Detailansicht mit Geltungsbereich, Zweck, Kurzbeschreibung, Beispieltexten, Artefakten und Kommentaren.",
            "Vorlage öffnen, Dokumentanker öffnen, zur Prüfung einreichen und Versionen nachvollziehen.",
            "Policies können mit Projektplan, Nachweisen, SoA und Aufgaben verknüpft werden.",
        ],
        [
            "Policy Management öffnen.",
            "Eine Policy anklicken und Dokument/Template öffnen.",
            "Erklärtexte und Beispiele zeigen: was gehört in dieses Dokument?",
        ],
        "Das Ziel ist, dass Kunden nicht nur eine Liste von Policy-Namen sehen, sondern direkt verstehen, was sie ausfüllen müssen und warum das Dokument relevant ist.",
    )
    module_block(
        doc,
        "5.2 Incident Management",
        "3 Minuten",
        "/#incidents",
        "Incidents und Security-Ereignisse werden strukturiert erfasst und in Aufgaben/Nachweise übersetzt.",
        [
            "Erfassung mit Titel, Schweregrad, Owner, Status, Termin und Erstbewertung.",
            "Verknüpfung zu Nachweisen, Aufgaben und Beraterprüfung.",
            "Kundensprache für Vorfälle: Was ist passiert? Welche Systeme sind betroffen? Welche Sofortmaßnahmen laufen?",
            "Review- und Lessons-Learned-Logik vorbereitet.",
        ],
        [
            "Incident-Formular zeigen.",
            "Registereintrag und Status erklären.",
            "Hinweis geben: Vorfallbewertung/Meldepflicht bleibt fachliche Aufgabe.",
        ],
        "Das Modul hilft, Vorfälle nicht nur zu notieren, sondern mit Nachweisen, Verantwortlichen und Folgeaufgaben abzuschließen.",
    )
    module_block(
        doc,
        "5.3 Contract Management",
        "2 Minuten",
        "/#contracts",
        "Verträge werden als Compliance-relevante Nachweise und Fristenobjekte geführt.",
        [
            "Vertragseinträge mit Owner, Status, Termin und Nachweisbezug.",
            "Verknüpfung zu Lieferanten, Aufgaben und Dokumentation.",
            "Review-Fälligkeiten und offene Vertragsnachweise sichtbar.",
        ],
        [
            "Einen Vertragseintrag zeigen.",
            "Verknüpfung zu Vendor Management erklären.",
        ],
        "Das ist wichtig, weil Lieferanten- und Sicherheitsbewertungen oft in Verträgen, Anlagen oder AVV-Nachweisen hängen.",
        page_break_before=True,
    )
    module_block(
        doc,
        "5.4 Integrationen",
        "2 Minuten",
        "/#integrations",
        "Integrationen sind aktuell als Roadmap und strukturierte Planung für spätere API-Anbindungen sichtbar.",
        [
            "Integration Roadmap mit Kategorien und geplanten Connectoren.",
            "Statuslogik für geplante, konfigurierte oder später produktive Anbindungen.",
            "Nutzbar für SIEM, SOC, Cloud, Ticketing, Dokumentenablage oder Collaboration-Systeme.",
            "Aktuell nicht als echte 60 Live-API-Anbindungen darstellen, sondern als vorbereitete Integrationsfähigkeit/Roadmap.",
        ],
        [
            "Integrationsseite öffnen und Status 0/60 erklären.",
            "Beispiele nennen: SIEM-Report, Cloud-Nachweise, Ticketing-Aufgaben.",
        ],
        "Hier sollte man sauber formulieren: Wir haben eine Integrationszentrale/Roadmap, echte produktive API-Anbindungen wären ein weiterer technischer Ausbauschritt.",
        ["Keine falsche Verkaufsbehauptung zu Live-Integrationen machen."],
    )
    module_block(
        doc,
        "5.5 Task Management",
        "3 Minuten",
        "/#tasks",
        "Task Management sammelt Aufgaben aus Kundenmodus, Projektplan, Review Center und Nacharbeit.",
        [
            "Aufgaben mit Owner, Status, Termin, Priorität und Modulbezug.",
            "Automatische Kundenaufgaben aus Nacharbeit im Review Center.",
            "Übersicht nach offen, in Bearbeitung, eingereicht, Nacharbeit, freigegeben.",
            "Verknüpfung zu Nachweisen, Risiken, Policies und Projektarbeitspaketen.",
        ],
        [
            "Aufgabe öffnen und Modulbezug zeigen.",
            "Nacharbeit aus Review Center erklären.",
        ],
        "Die Aufgabenlogik macht die Plattform alltagstauglich: Niemand soll wissen müssen, aus welchem Modul eine Aufgabe kommt; entscheidend ist, was jetzt zu tun ist.",
        page_break_before=True,
    )


def add_admin_modules(doc):
    doc.add_page_break()
    heading(doc, "6. Administration, Produktivbetrieb und Nachvollziehbarkeit", 1)
    module_block(
        doc,
        "6.1 Team & Einladungen",
        "3 Minuten",
        "/#team",
        "Kunden können Mitarbeiter einladen und Rollen für Mitarbeit im Projekt vorbereiten.",
        [
            "Einladungsbereich für Mitarbeitende im Kundenprojekt.",
            "Rollenlogik: Kunde/Mitwirkender/Berater/Admin je nach Berechtigung.",
            "Einladungsstatus, Token-/Link-Logik und Onboarding-Hinweise.",
            "Grundlage für echte Mehrbenutzerfähigkeit im Produktivbetrieb.",
        ],
        [
            "Team & Einladungen öffnen.",
            "Rollenlogik erklären: Kunde bearbeitet, Berater prüft, Admin steuert.",
        ],
        "Für echte Kundenprojekte ist das zentral, weil nicht eine Person alle Informationen kennt. Fachbereiche müssen eingebunden werden können.",
    )
    module_block(
        doc,
        "6.2 Mein Konto und Zugriffslogik",
        "2 Minuten",
        "/#account",
        "Mein Konto zeigt den persönlichen Sicherheits- und Zugriffsbereich.",
        [
            "Profil-/Sessionbereich.",
            "Passwort-/MFA-Hinweise.",
            "Trennung zwischen Kundenrolle, Beraterrolle und Admin-Funktionen.",
            "Im Produktivbetrieb relevant für echte Authentifizierung und Rollenrechte.",
        ],
        [
            "Konto-Bereich öffnen.",
            "Betonen, dass produktive Freigaben echte serverseitige Rollenrechte brauchen.",
        ],
        "Hier sieht man die Sicherheitslogik aus Nutzersicht. Für einen echten Produktivbetrieb muss diese Logik serverseitig abgesichert sein.",
    )
    module_block(
        doc,
        "6.3 Produktivbetrieb und Betriebsmonitor",
        "4 Minuten",
        "/#production und /#operations",
        "Diese Bereiche zeigen, was für einen professionellen Betrieb noch überwacht oder gehärtet werden muss.",
        [
            "Produktions-Checklisten für Authentifizierung, Rollenrechte, Dateiablage, Logging, Betrieb, Backup und Datenschutz.",
            "Betriebsmonitor mit Health-/Runtime-/Alert-Sicht.",
            "Systemdiagnosen und Wartungsaktionen.",
            "Klare Unterscheidung zwischen Prototyp/Entwicklungsstand und produktivem Kundenbetrieb.",
        ],
        [
            "Produktivbetrieb öffnen und Checklisten zeigen.",
            "Betriebsmonitor/Health-Status zeigen.",
        ],
        "Das ist für interne Steuerung wichtig: Wir können Kundenfunktionen zeigen, aber für echten Produktivbetrieb braucht es Auth, Rollen, Logging, sichere Dateiablage, Monitoring und Betriebsprozesse.",
        page_break_before=True,
    )
    module_block(
        doc,
        "6.4 Backup & Recovery und Datenlebenszyklus",
        "3 Minuten",
        "/#backup und /#lifecycle",
        "Backup und Datenlebenszyklus zeigen, wie Daten später kontrolliert aufbewahrt, gesichert und gelöscht werden.",
        [
            "Backup-Readiness, Snapshots und Wiederherstellungsstatus.",
            "Datenlebenszyklus mit Aufbewahrung, Löschlogik, Verantwortlichkeiten und Tenant-Bezug.",
            "Wichtig für Betriebs- und Datenschutzanforderungen.",
        ],
        [
            "Backup- und Lifecycle-Ansicht öffnen.",
            "Aufbewahrung und Wiederherstellung als Betriebsfähigkeit erklären.",
        ],
        "Für Kunden ist wichtig: Die Plattform soll nicht nur Daten sammeln, sondern Daten auch kontrolliert verwalten können.",
    )
    module_block(
        doc,
        "6.5 Audit Trail und Versionierung",
        "4 Minuten",
        "/#audittrail",
        "Audit Trail macht Änderungen, Einreichungen, Freigaben, Rückgaben und Versionen nachvollziehbar.",
        [
            "Ereignishistorie: Wer hat was wann geändert?",
            "Einreichungen, Freigaben, Ablehnungen und Nacharbeit werden protokolliert.",
            "Versionierung für Policies und Nachweise.",
            "Filter für Events, Versionen, Module, Personen und Zeiträume.",
            "Wichtig für Revisionssicherheit und spätere Audit-Nachvollziehbarkeit.",
        ],
        [
            "Audit Trail öffnen.",
            "Ein Event und eine Version zeigen.",
            "Erklären, warum alte Policy-/Nachweisversionen wichtig sind.",
        ],
        "Das ist einer der professionellsten Bausteine: Nicht nur der aktuelle Stand zählt, sondern auch, wie man dort hingekommen ist.",
        page_break_before=True,
    )


def add_status_roles_and_close(doc):
    doc.add_page_break()
    heading(doc, "7. Status-, Rollen- und Freigabelogik", 1)
    para(doc, "Diese Logik sollte im Vortrag bewusst erklärt werden, weil sie zeigt, dass die Plattform den Berater nicht ersetzt.")
    status_rows = [
        ("offen", "Noch nicht bearbeitet oder noch nicht eingereicht.", "Kunde/Berater"),
        ("vom_kunden_eingereicht", "Kunde hat Informationen oder Nachweise zur Prüfung abgegeben.", "Kunde"),
        ("in_beraterpruefung", "Berater/Admin prüft fachlich oder formal.", "Berater/Admin"),
        ("nacharbeit_noetig", "Es fehlt etwas; Kunde bekommt eine konkrete Rückgabeaufgabe.", "Berater/Admin"),
        ("freigegeben", "Fachlich durch Berater/Admin freigegeben.", "Berater/Admin"),
        ("abgelehnt", "Nicht verwendbar oder fachlich nicht akzeptiert.", "Berater/Admin"),
        ("auditrelevant", "Für Auditpaket oder Auditspur relevant markiert.", "Berater/Admin"),
    ]
    table = doc.add_table(rows=1, cols=3)
    fixed_table(table, [1.7, 3.55, 1.35])
    for cell, text in zip(table.rows[0].cells, ["Status", "Bedeutung", "Wer darf setzen?"]):
        shade(cell, "E8EEF5")
        border(cell)
        cell_text(cell, text, bold=True)
    for values in status_rows:
        row = table.add_row()
        keep_row(row)
        for cell, text in zip(row.cells, values):
            border(cell)
            cell_text(cell, text, size=9)
    doc.add_paragraph()

    heading(doc, "8. Was besonders vorzeigbar ist", 1)
    highlights = [
        "Geführter Kundenmodus: reduziert Komplexität und zeigt nur den nächsten sinnvollen Schritt.",
        "Review Center: Berater bleibt fachliche Kontrollinstanz.",
        "Auditpaket-Gate: vorbereitet ist nicht automatisch auditbereit.",
        "Policy- und Template-Logik: Kunden bekommen nicht nur Namen, sondern Hilfetexte, Beispiele und verlinkte Dokumente.",
        "Register-Logik: Assets, Risiken, Lieferanten, Rechtsthemen und Nachweise hängen zusammen.",
        "Audit Trail und Versionierung: Änderungen und alte Dokumentstände bleiben nachvollziehbar.",
    ]
    for item in highlights:
        bullet(doc, item)

    heading(doc, "9. Empfohlene Abschlussfolie / Abschlussformulierung", 1)
    callout(
        doc,
        "Abschluss",
        "SFM Compliance ist eine Arbeitsplattform für die ISMS-/ISO-27001-/NIS-2-Vorbereitung. Kunden werden einfach geführt, Nachweise und Aufgaben werden strukturiert, Lücken werden sichtbar und Berater/Admin behalten die fachliche Entscheidung. Genau diese Trennung macht die Plattform professionell: Sie automatisiert Organisation, aber nicht Verantwortung.",
        fill=LIGHT_TEAL,
    )
    heading(doc, "10. Nächste sinnvolle Ausbaustufen", 1)
    next_steps = [
        "Echte produktive Dateiablage mit Verschlüsselung, Rollenrechten und Mandantentrennung.",
        "Serverseitig erzwungene Rollenrechte für Kunde, Berater und Admin.",
        "Exportfähiges Auditpaket mit Freigabestatus, Versionsliste und Nachweisindex.",
        "Mehr Mandanten/Kundenprojekte mit Projektumschalter und getrennten Datenräumen.",
        "Produktive Integrationen: SIEM/SOC, Ticketing, Cloud, DMS und Collaboration-Tools.",
        "Feinschliff für Präsentationsdesign und konsistente Kunden-Hilfetexte in allen Formularen.",
    ]
    for item in next_steps:
        bullet(doc, item)


def build():
    doc = Document()
    section = doc.sections[0]
    section.orientation = WD_ORIENT.PORTRAIT
    section.top_margin = Inches(0.55)
    section.bottom_margin = Inches(0.55)
    section.left_margin = Inches(0.55)
    section.right_margin = Inches(0.55)
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)

    add_header_footer(doc)
    add_cover(doc)
    doc.add_page_break()
    add_agenda(doc)
    add_overview_modules(doc)
    add_compliance_modules(doc)
    add_register_modules(doc)
    add_operations_modules(doc)
    add_admin_modules(doc)
    add_status_roles_and_close(doc)
    doc.save(OUT)
    print(OUT)


if __name__ == "__main__":
    build()
