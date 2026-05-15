from pathlib import Path
from pypdf import PdfReader
pdf = Path(r"""C:\\Users\\agraw\\OneDrive\\Desktop\\Rufrone_MiniProject_LaTeX_v2 (1).pdf""")
reader = PdfReader(str(pdf))
for i,p in enumerate(reader.pages,1):
    print(f"\n===== PAGE {i} =====\n")
    txt = p.extract_text() or ""
    print(txt)
