"""Builds risk-register.xlsx: a ready-to-use risk register for GRC and AI Assurance (lesson 1.2).

Run:  python3 build_register_xlsx.py            (writes risk-register.xlsx next to this file)

Sheets
  How to use  what to fill in, the column guide and the review routine
  Register    one row per risk; you type in the white cells, the gray cells are formulas
  Scales      the 1 to 5 likelihood and impact scales, the rating bands and the risk appetite (edit these to fit)
  Heat map    5 x 5 counts of risks by likelihood and impact, before and after treatment
  Dashboard   counts by rating, status and owner, overdue actions and risks above appetite
  Lists       the drop-down choices (categories, owners, responses, statuses)

Everything in the example rows is made up (Example Corp). Delete the examples, or keep them as a guide.
The lesson's web-app prompt asks for the same columns, so a CSV of the Register sheet imports into the app.
"""
from datetime import date
from pathlib import Path

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

OUT = Path(__file__).with_name("risk-register.xlsx")
ROWS = 300  # formula rows prepared on the Register sheet
FONT = "Arial"

INK, MUTED, LINE = "0A1020", "4A5570", "D6CCB8"
HEAD_FILL = PatternFill("solid", fgColor="0A1020")
INPUT_FILL = PatternFill("solid", fgColor="FFFFFF")
CALC_FILL = PatternFill("solid", fgColor="ECE5D6")
BAND = {"Low": "C8EBDD", "Medium": "FFE7A8", "High": "FFC9A8", "Critical": "F4A6A0"}
thin = Side(style="thin", color=LINE)
BOX = Border(left=thin, right=thin, top=thin, bottom=thin)

CATEGORIES = ["Cyber security", "AI", "Data protection", "Third party", "Operational", "People", "Compliance", "Financial"]
OWNERS = ["Head of IT Operations", "CISO", "Head of Support", "Head of Engineering", "Data Protection Officer",
          "Head of Procurement", "Head of HR", "CFO"]
RESPONSES = ["Mitigate", "Accept", "Transfer", "Avoid"]
STATUSES = ["Open", "In progress", "Done", "Accepted", "Closed"]

# column key, header, width, kind ("in" = you type it, "calc" = formula)
COLS = [
    ("id", "ID", 8, "in"),
    ("risk", "Risk (cause, event, impact)", 46, "in"),
    ("category", "Category", 16, "in"),
    ("asset", "Asset or process", 20, "in"),
    ("owner", "Risk owner", 22, "in"),
    ("raised", "Date raised", 12, "in"),
    ("likelihood", "Likelihood (1-5)", 11, "in"),
    ("impact", "Impact (1-5)", 10, "in"),
    ("score", "Inherent score", 10, "calc"),
    ("rating", "Inherent rating", 11, "calc"),
    ("controls", "Existing controls", 30, "in"),
    ("response", "Response", 11, "in"),
    ("action", "Action plan", 34, "in"),
    ("action_owner", "Action owner", 20, "in"),
    ("due", "Due date", 12, "in"),
    ("status", "Status", 12, "in"),
    ("res_likelihood", "Residual likelihood (1-5)", 12, "in"),
    ("res_impact", "Residual impact (1-5)", 11, "in"),
    ("res_score", "Residual score", 10, "calc"),
    ("res_rating", "Residual rating", 11, "calc"),
    ("appetite", "Within appetite?", 11, "calc"),
    ("accepted_by", "Accepted by (if accepted)", 20, "in"),
    ("last_review", "Last review", 12, "in"),
    ("next_review", "Next review", 12, "calc"),
    ("overdue", "Action overdue?", 10, "calc"),
    ("notes", "Notes", 30, "in"),
]
C = {key: get_column_letter(i + 1) for i, (key, *_rest) in enumerate(COLS)}

EXAMPLES = [
    ["R-001", "No offline backups, so ransomware that encrypts the customer database causes a 3-day outage.", "Cyber security",
     "Customer database", "Head of IT Operations", date(2026, 1, 12), 3, 5, "Daily backups (online only), endpoint protection",
     "Mitigate", "Immutable offline backups and quarterly restore tests", "Head of IT Operations", date(2026, 6, 30), "In progress",
     2, 3, "", date(2026, 10, 1), "Lesson 1.2 example R-014, renumbered"],
    ["R-002", "Staff paste customer data into unapproved AI tools, so personal data leaks to a supplier with no contract.", "AI",
     "Customer support", "CISO", date(2026, 2, 3), 4, 4, "AI policy; one approved assistant", "Mitigate",
     "Find shadow AI in proxy logs; approve a safe option; train support staff", "CISO", date(2026, 3, 31), "Done",
     2, 3, "", date(2026, 11, 2), "See lesson 3.6"],
    ["R-003", "HelpBot's refund limit lives only in its prompt, so refunds over $100 can be paid without approval.", "AI",
     "HelpBot refunds", "Head of Support", date(2026, 8, 4), 3, 3, "Limit stated in the system prompt", "Mitigate",
     "Enforce the limit and approval step in the refund tool; re-test", "Head of Engineering", date(2026, 9, 30), "In progress",
     1, 3, "", date(2026, 10, 15), "Audit finding, lesson 3.5"],
    ["R-004", "The model provider changes or retires the model without notice, so HelpBot's answers change untested.", "Third party",
     "HelpBot", "Head of Procurement", date(2026, 4, 8), 4, 4, "Supplier review SUP-19", "Transfer",
     "Add change-notice and testing clauses at renewal", "Head of Procurement", date(2027, 2, 28), "Open",
     3, 4, "", date(2026, 10, 1), "Still above appetite after the plan: escalate"],
    ["R-005", "A phishing email steals an admin's password, so an attacker changes billing settings.", "Cyber security",
     "Billing platform", "CISO", date(2026, 1, 20), 4, 4, "MFA for admins; phishing training", "Mitigate",
     "Phishing-resistant MFA (security keys) for all admins", "Head of IT Operations", date(2026, 5, 31), "Done",
     1, 4, "", date(2026, 9, 1), ""],
    ["R-006", "A storage bucket is created without encryption, so debug logs sit unencrypted.", "Data protection",
     "Cloud storage", "Head of Engineering", date(2026, 11, 20), 3, 2, "Daily configuration check", "Mitigate",
     "Turn on default encryption; alert and ticket on every failed check", "Head of Engineering", date(2026, 12, 15), "Open",
     1, 2, "", date(2026, 11, 20), "Found by continuous monitoring, lesson 4.1"],
    ["R-007", "Only one engineer knows the billing deployment, so an absence delays urgent fixes.", "People",
     "Billing platform", "Head of Engineering", date(2026, 3, 2), 3, 3, "Runbook (out of date)", "Accept",
     "", "", None, "Accepted", 3, 3, "CFO", date(2026, 9, 15), "Accepted until the 2027 hiring plan"],
    ["R-008", "A new EU customer needs AI Act transparency notices we haven't written, so the deal is delayed.", "Compliance",
     "Sales", "Data Protection Officer", date(2026, 10, 5), 2, 3, "Privacy notice", "Mitigate",
     "Write the chatbot disclosure and check it with counsel", "Data Protection Officer", date(2026, 12, 31), "Open",
     1, 2, "", date(2026, 10, 5), "See lesson 3.3"],
]


def head(ws, row, values, widths=None):
    for i, v in enumerate(values, start=1):
        c = ws.cell(row=row, column=i, value=v)
        c.font = Font(name=FONT, bold=True, color="FFFFFF")
        c.fill = HEAD_FILL
        c.alignment = Alignment(wrap_text=True, vertical="center")
        c.border = BOX
        if widths:
            ws.column_dimensions[get_column_letter(i)].width = widths[i - 1]


def text(ws, ref, value, bold=False, size=10, color=INK, wrap=True):
    c = ws[ref]
    c.value = value
    c.font = Font(name=FONT, bold=bold, size=size, color=color)
    c.alignment = Alignment(wrap_text=wrap, vertical="top")
    return c


def build():
    wb = Workbook()

    # ---------------- How to use ----------------
    hw = wb.active
    hw.title = "How to use"
    hw.column_dimensions["A"].width = 24
    hw.column_dimensions["B"].width = 96
    text(hw, "A1", "Risk register", bold=True, size=16)
    text(hw, "A2", "GRC and AI Assurance, lesson 1.2. Example rows are made up (Example Corp): delete them or keep them as a guide.",
         color=MUTED)
    hw.merge_cells("A2:B2")
    rows = [
        ("What it is", "One row per risk: what could go wrong, who owns it, how likely and how bad, what you are doing about it, and how it looks after treatment."),
        ("Cells you edit", "White cells on the Register sheet. Gray cells are formulas: score, rating, appetite check, next review date and overdue flag. Don't type over them."),
        ("Write the risk", "Cause, event, impact in one sentence: \"No offline backups, so ransomware that encrypts the customer database causes a 3-day outage.\""),
        ("Owner", "A business role that can decide and fund the fix, not the security team. Pick from the list or add roles on the Lists sheet."),
        ("Likelihood and impact", "Whole numbers 1 to 5, defined on the Scales sheet. Score = likelihood x impact (1 to 25)."),
        ("Inherent and residual", "Inherent = today, with existing controls. Residual = after the action plan is done. The gap shows what the plan buys."),
        ("Response", "Mitigate (reduce it), Accept (live with it; name who accepted), Transfer (insurance or contract), Avoid (stop the activity)."),
        ("Risk appetite", "The highest residual score leadership will accept without escalation, set on the Scales sheet (example: 9)."),
        ("Review routine", "Owners review their risks on the cadence in Scales (Critical monthly, High quarterly, Medium half-yearly, Low yearly). Update Last review each time."),
        ("Heat map and Dashboard", "Update themselves from the Register. Use them for the one-page board report (lesson 2.8)."),
        ("Moving to a web app", "Lesson 1.2 has a prompt that builds a small risk register web app with these same columns. Save the Register sheet as CSV (File > Save As > CSV) to import your rows into it."),
        ("Keep it private", "A risk register lists your weaknesses. Store it where only the people who need it can open it. Never in a public folder or a public bucket."),
    ]
    for i, (k, v) in enumerate(rows, start=4):
        text(hw, f"A{i}", k, bold=True)
        text(hw, f"B{i}", v)
        hw.row_dimensions[i].height = 32
    key_row = 4 + len(rows) + 1
    text(hw, f"A{key_row}", "Color key", bold=True)
    hw[f"B{key_row}"].value = "White = you type   Gray = formula   Low / Medium / High / Critical shading = rating band"
    hw[f"B{key_row}"].font = Font(name=FONT, size=10)

    # ---------------- Lists ----------------
    ls = wb.create_sheet("Lists")
    head(ls, 1, ["Category", "Owner", "Response", "Status"], [20, 28, 14, 14])
    for col, values in enumerate([CATEGORIES, OWNERS, RESPONSES, STATUSES], start=1):
        for r, v in enumerate(values, start=2):
            ls.cell(row=r, column=col, value=v).font = Font(name=FONT)
    text(ls, "F1", "Add your own categories or owner roles at the end of a column (up to row 40). The drop-downs pick them up.", color=MUTED)
    ls.column_dimensions["F"].width = 60

    # ---------------- Scales ----------------
    sc = wb.create_sheet("Scales")
    sc.column_dimensions["A"].width = 10
    sc.column_dimensions["B"].width = 16
    sc.column_dimensions["C"].width = 70
    text(sc, "A1", "Likelihood (in the next 12 months)", bold=True, size=12)
    head(sc, 2, ["Score", "Label", "Meaning"])
    for r, (s, lab, mean) in enumerate([
        (1, "Rare", "Less than 5% chance; not seen here or at peers"),
        (2, "Unlikely", "5 to 20%; seen at peers, not here"),
        (3, "Possible", "20 to 50%; has happened here, or could with one control failing"),
        (4, "Likely", "50 to 80%; happens most years"),
        (5, "Almost certain", "Over 80%; happening now or expected"),
    ], start=3):
        for c, v in enumerate((s, lab, mean), start=1):
            sc.cell(row=r, column=c, value=v).font = Font(name=FONT)
    text(sc, "A9", "Impact (if it happens)", bold=True, size=12)
    head(sc, 10, ["Score", "Label", "Meaning (edit the money figures to fit your company)"])
    for r, (s, lab, mean) in enumerate([
        (1, "Minimal", "Under $10,000; no customer notices; no regulator interest"),
        (2, "Minor", "$10,000 to $100,000; a few customers affected for hours"),
        (3, "Moderate", "$100,000 to $1M; outage under a day; a complaint to a regulator"),
        (4, "Major", "$1M to $5M; multi-day outage; reportable breach"),
        (5, "Severe", "Over $5M; loss of a key customer or license; fines; headlines"),
    ], start=11):
        for c, v in enumerate((s, lab, mean), start=1):
            sc.cell(row=r, column=c, value=v).font = Font(name=FONT)
    text(sc, "A17", "Rating bands (score = likelihood x impact)", bold=True, size=12)
    head(sc, 18, ["From score", "Rating", "Review every (days)"])
    bands = [(1, "Low", 365), (5, "Medium", 180), (10, "High", 90), (20, "Critical", 30)]
    for r, (lo, lab, days) in enumerate(bands, start=19):
        sc.cell(row=r, column=1, value=lo).font = Font(name=FONT, color="0000FF")
        cell = sc.cell(row=r, column=2, value=lab)
        cell.font = Font(name=FONT, bold=True)
        cell.fill = PatternFill("solid", fgColor=BAND[lab])
        sc.cell(row=r, column=3, value=days).font = Font(name=FONT, color="0000FF")
    text(sc, "A24", "Risk appetite: highest residual score accepted without escalation", bold=True)
    sc.merge_cells("A24:C24")
    sc["A25"].value = 9
    sc["A25"].font = Font(name=FONT, bold=True, color="0000FF")
    sc["A25"].fill = PatternFill("solid", fgColor="FFFF00")
    text(sc, "B25", "Example value set by leadership. Change it to yours.", color=MUTED)
    sc.merge_cells("B25:C25")
    text(sc, "A27", "Blue numbers are settings you can change. The Register's ratings, appetite check and review dates follow them.", color=MUTED)
    sc.merge_cells("A27:C27")

    BANDS = "Scales!$A$19:$B$22"
    DAYS = "Scales!$A$19:$C$22"
    APPETITE = "Scales!$A$25"

    # ---------------- Register ----------------
    rg = wb.create_sheet("Register", 1)
    head(rg, 1, [h for _, h, _, _ in COLS], [w for _, _, w, _ in COLS])
    rg.row_dimensions[1].height = 42
    rg.freeze_panes = "C2"
    for r in range(2, ROWS + 2):
        L, I, RL, RI = (f"{C[k]}{r}" for k in ("likelihood", "impact", "res_likelihood", "res_impact"))
        formulas = {
            "score": f'=IF(OR({L}="",{I}=""),"",{L}*{I})',
            "rating": f'=IF({C["score"]}{r}="","",VLOOKUP({C["score"]}{r},{BANDS},2,TRUE))',
            "res_score": f'=IF(OR({RL}="",{RI}=""),"",{RL}*{RI})',
            "res_rating": f'=IF({C["res_score"]}{r}="","",VLOOKUP({C["res_score"]}{r},{BANDS},2,TRUE))',
            "appetite": f'=IF({C["res_score"]}{r}="","",IF({C["res_score"]}{r}<={APPETITE},"Yes","No"))',
            "next_review": (f'=IF(OR({C["last_review"]}{r}="",{C["score"]}{r}=""),"",'
                            f'{C["last_review"]}{r}+VLOOKUP(IF({C["res_score"]}{r}="",{C["score"]}{r},{C["res_score"]}{r}),{DAYS},3,TRUE))'),
            "overdue": (f'=IF(OR({C["due"]}{r}="",{C["status"]}{r}="Done",{C["status"]}{r}="Closed",'
                        f'{C["status"]}{r}="Accepted"),"",IF({C["due"]}{r}<TODAY(),"Yes","No"))'),
        }
        for key, _, _, kind in COLS:
            cell = rg[f"{C[key]}{r}"]
            cell.font = Font(name=FONT, size=10)
            cell.border = BOX
            cell.alignment = Alignment(wrap_text=key in ("risk", "controls", "action", "notes"), vertical="top")
            if kind == "calc":
                cell.value = formulas[key]
                cell.fill = CALC_FILL
            else:
                cell.fill = INPUT_FILL
            if key in ("raised", "due", "last_review", "next_review"):
                cell.number_format = "yyyy-mm-dd"
    for r, row in enumerate(EXAMPLES, start=2):
        keys = [k for k, _, _, kind in COLS if kind == "in"]
        for key, value in zip(keys, row):
            rg[f"{C[key]}{r}"].value = value

    last = ROWS + 1
    def dv(formula, cols, title, prompt, kind="list"):
        if kind == "list":
            v = DataValidation(type="list", formula1=formula, allow_blank=True)
        else:
            v = DataValidation(type="whole", operator="between", formula1="1", formula2="5", allow_blank=True)
        v.error, v.errorTitle, v.prompt, v.promptTitle = "Pick a value from the list.", title, prompt, title
        v.showErrorMessage = True
        rg.add_data_validation(v)
        for col in cols:
            v.add(f"{C[col]}2:{C[col]}{last}")
    dv("Lists!$A$2:$A$40", ["category"], "Category", "Pick a category (edit the list on the Lists sheet).")
    dv("Lists!$B$2:$B$40", ["owner", "action_owner"], "Owner", "Pick an owner role (edit the list on the Lists sheet).")
    dv("Lists!$C$2:$C$5", ["response"], "Response", "Mitigate, Accept, Transfer or Avoid.")
    dv("Lists!$D$2:$D$6", ["status"], "Status", "Pick a status.")
    dv(None, ["likelihood", "impact", "res_likelihood", "res_impact"], "Score 1 to 5", "A whole number from 1 to 5 (see Scales).", kind="whole")

    for key in ("rating", "res_rating"):
        rng = f"{C[key]}2:{C[key]}{last}"
        for lab, colour in BAND.items():
            rg.conditional_formatting.add(rng, FormulaRule(formula=[f'{C[key]}2="{lab}"'], fill=PatternFill("solid", fgColor=colour),
                                                           font=Font(name=FONT, bold=True, color=INK)))
    for key in ("appetite", "overdue"):
        bad = "No" if key == "appetite" else "Yes"
        rng = f"{C[key]}2:{C[key]}{last}"
        rg.conditional_formatting.add(rng, FormulaRule(formula=[f'{C[key]}2="{bad}"'], fill=PatternFill("solid", fgColor=BAND["Critical"]),
                                                       font=Font(name=FONT, bold=True, color=INK)))
    rg.auto_filter.ref = f"A1:{C['notes']}{last}"

    REG = lambda key: f"Register!${C[key]}$2:${C[key]}${last}"  # noqa: E731

    # ---------------- Heat map ----------------
    hm = wb.create_sheet("Heat map")
    hm.column_dimensions["A"].width = 22
    for col in "BCDEF":
        hm.column_dimensions[col].width = 12
    for top, title, lk, ik in ((1, "Inherent risk (today)", "likelihood", "impact"),
                               (12, "Residual risk (after the action plan)", "res_likelihood", "res_impact")):
        text(hm, f"A{top}", title, bold=True, size=12)
        text(hm, f"A{top + 1}", "Number of risks. Rows: likelihood. Columns: impact.", color=MUTED)
        hm.merge_cells(f"A{top + 1}:F{top + 1}")
        hm.cell(row=top + 2, column=1, value="Likelihood \\ Impact").font = Font(name=FONT, bold=True)
        for i in range(1, 6):
            c = hm.cell(row=top + 2, column=i + 1, value=i)
            c.font = Font(name=FONT, bold=True)
            c.alignment = Alignment(horizontal="center")
        for j, lik in enumerate(range(5, 0, -1)):
            row = top + 3 + j
            hm.cell(row=row, column=1, value=lik).font = Font(name=FONT, bold=True)
            for imp in range(1, 6):
                score = lik * imp
                band = [b for lo, b, _ in reversed(bands) if score >= lo][0]
                c = hm.cell(row=row, column=imp + 1, value=f'=COUNTIFS({REG(lk)},{lik},{REG(ik)},{imp})')
                c.fill = PatternFill("solid", fgColor=BAND[band])
                c.font = Font(name=FONT, bold=True, size=12)
                c.alignment = Alignment(horizontal="center", vertical="center")
                c.border = BOX
                hm.row_dimensions[row].height = 26
    text(hm, "A23", "Cell colors use the default rating bands (Scales sheet). If you change the bands, the counts stay right; recolor the cells to match.", color=MUTED)
    hm.merge_cells("A23:F24")

    # ---------------- Dashboard ----------------
    db = wb.create_sheet("Dashboard", 2)
    db.column_dimensions["A"].width = 28
    for col in "BC":
        db.column_dimensions[col].width = 14
    text(db, "A1", "Risk dashboard", bold=True, size=16)
    text(db, "A2", "Counts update from the Register sheet.", color=MUTED)
    stats = [
        ("Risks in the register", f'=COUNTA({REG("id")})'),
        ("Residual score above appetite", f'=COUNTIF({REG("appetite")},"No")'),
        ("Actions overdue", f'=COUNTIF({REG("overdue")},"Yes")'),
        ("Reviews due (next review passed)", f'=COUNTIFS({REG("next_review")},"<"&TODAY())'),
        ("Risks accepted", f'=COUNTIF({REG("status")},"Accepted")'),
    ]
    head(db, 4, ["Headline", "Count"])
    for i, (lab, f) in enumerate(stats, start=5):
        db.cell(row=i, column=1, value=lab).font = Font(name=FONT)
        c = db.cell(row=i, column=2, value=f)
        c.font = Font(name=FONT, bold=True)
        c.fill = CALC_FILL
    r0 = 5 + len(stats) + 1
    head(db, r0, ["Rating", "Inherent", "Residual"])
    for i, (_, lab, _) in enumerate(bands, start=r0 + 1):
        c = db.cell(row=i, column=1, value=lab)
        c.font = Font(name=FONT, bold=True)
        c.fill = PatternFill("solid", fgColor=BAND[lab])
        db.cell(row=i, column=2, value=f'=COUNTIF({REG("rating")},A{i})').font = Font(name=FONT)
        db.cell(row=i, column=3, value=f'=COUNTIF({REG("res_rating")},A{i})').font = Font(name=FONT)
    r1 = r0 + len(bands) + 2
    head(db, r1, ["Status", "Risks"])
    for i, s in enumerate(STATUSES, start=r1 + 1):
        db.cell(row=i, column=1, value=s).font = Font(name=FONT)
        db.cell(row=i, column=2, value=f'=COUNTIF({REG("status")},A{i})').font = Font(name=FONT)
    r2 = r1 + len(STATUSES) + 2
    head(db, r2, ["Risk owner", "Risks owned", "Above appetite"])
    for i in range(len(OWNERS)):
        row = r2 + 1 + i
        db.cell(row=row, column=1, value=f"=IF(Lists!B{i + 2}=\"\",\"\",Lists!B{i + 2})").font = Font(name=FONT)
        db.cell(row=row, column=2, value=f'=IF(A{row}="","",COUNTIF({REG("owner")},A{row}))').font = Font(name=FONT)
        db.cell(row=row, column=3, value=f'=IF(A{row}="","",COUNTIFS({REG("owner")},A{row},{REG("appetite")},"No"))').font = Font(name=FONT)

    wb.active = 1  # open on the Register
    wb.save(OUT)
    print(f"wrote {OUT.name}: {len(EXAMPLES)} example risks, {ROWS} rows ready")


if __name__ == "__main__":
    build()
