# GRC and AI Assurance: templates

Free templates for the **GRC and AI Assurance** course by [The Sec Guy](https://thesecguy.com/course/).

## Risk register (lesson 1.2)

[`risk-register/risk-register.xlsx`](risk-register/risk-register.xlsx) is a ready-to-use risk register. It opens in
Excel, Google Sheets, LibreOffice Calc and Numbers.

| Sheet | What it holds |
|---|---|
| How to use | What to fill in, the column guide and the review routine |
| Register | One row per risk: risk, category, owner, likelihood, impact, scores and ratings, controls, response, action plan, due date, status, residual risk, appetite check, review dates |
| Dashboard | Counts by rating, status and owner; overdue actions; risks above appetite |
| Scales | The 1 to 5 likelihood and impact scales, rating bands, review cadence and risk appetite (change them to fit) |
| Heat map | 5 x 5 counts of risks before and after treatment |
| Lists | The drop-down choices (categories, owner roles, responses, statuses) |

You type in the white cells; the gray cells are formulas. The eight example rows are for a made-up company
(Example Corp): delete them or keep them as a guide.

**Download:** open the file link above and press the download button (top right of the file view), or clone the repo.

**Keep your copy private.** A filled-in risk register lists your organization's weaknesses. Store it where only the
people who need it can open it.

To rebuild the file after changing the template (needs `pip install openpyxl`):

```bash
cd labs/grc/risk-register
python3 build_register_xlsx.py
```
