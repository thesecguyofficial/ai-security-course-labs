"""
package.py: zip lambda/handler.py into build/helpdesk.zip for each Terraform folder (`make package`).

Deterministic (fixed timestamp), so the zip's hash, and therefore the plan, only changes when the code does.
Standard library only.
"""

import pathlib
import zipfile

HERE = pathlib.Path(__file__).resolve().parent

for folder in ("terraform/hardened", "terraform/first-draft"):
    src = HERE / folder / "lambda" / "handler.py"
    out = HERE / folder / "build" / "helpdesk.zip"
    out.parent.mkdir(exist_ok=True)
    info = zipfile.ZipInfo("handler.py", date_time=(2026, 10, 1, 0, 0, 0))
    info.external_attr = 0o644 << 16
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(info, src.read_bytes())
    print(f"wrote {out.relative_to(HERE)}")
