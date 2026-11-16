# CTF W6 · OSINT — write-up

## OSINT — Document author (50 pts)

**Evidence:** `DN-5583_verhaegen.pdf` — a legitimate supplier document (the
delivery note Tom Verhaegen references in the real PO-88214 thread, see the
Email write-up).

**Ask:** who authored it? The answer is not in the visible text.

The rendered page only shows a one-line stamp — "Verhaegen Packaging BV -
Delivery note DN-5583 - PO-88214 - Hamilton Corp" — no author name anywhere
visible. The file is a tiny (849-byte) hand-built PDF, so its raw object
structure is plain enough to read directly rather than needing a PDF-metadata
tool: fetching the file and reading it as text turns up its `/Info`
dictionary (object 6), which carries the real author in the PDF's metadata,
separate from the page content stream (object 4):

```
6 0 obj
<< /Title (Delivery note DN-5583) /Author (Tom Verhaegen)
   /Creator (Verhaegen Packaging ERP) /Producer (Verhaegen Packaging ERP) >>
endobj
```

**Flag:** `Tom Verhaegen`

---

Submitted and accepted on CTFd (50 pts for the category).
