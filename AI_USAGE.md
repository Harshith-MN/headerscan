# AI Usage Disclosure

> **READ ME FIRST (delete this block before submitting):** The answers marked **[YOU MUST FILL IN]** can only be true if YOU did the work. Run the tool, read `headerscan.py` line by line, break it on purpose, and write what actually happened in your own words. Do not submit this file unedited. Hiding AI usage or being unable to explain the code can disqualify you.

## 1. Which AI tools did you use?
Claude (Anthropic), via the Claude mobile app.

## 2. How did AI assist you?
Claude proposed the project idea (false-positive-aware header/cookie analyser), designed the rule set, and wrote the initial `headerscan.py`, the sample inputs, the unit tests, and the first drafts of `README.md` and this file. **[YOU MUST FILL IN: what you asked, how many iterations, what you did yourself.]**

## 3. Which parts were generated or substantially suggested by AI?
Substantially all of the first version: parser, all `check_*` functions, report rendering, tests, samples, README. **[YOU MUST FILL IN: anything you wrote or redesigned yourself.]**

## 4. Mistakes, insecure suggestions or incorrect assumptions made by AI
**[YOU MUST FILL IN from your own review.]** Places to look and test:
- The initial parser treats a new `HTTP/` line as a new response; what happens if a response body contains one? (README lists this as a limitation.)
- Cookie sensitivity is a name regex. Try `Set-Cookie: x1=...` and `Set-Cookie: csrf_session=...`. Is the result right?
- Is "ACAO `*` + credentials = medium" the right severity, given browsers block it? Check MDN.
- Is "missing Referrer-Policy = info" right in current browsers?
- Verify the RFC 6797 claim that HSTS is ignored over HTTP.

## 5. How did you manually validate the generated code/output?
**[YOU MUST FILL IN.]** Suggestions: ran `python3 -m unittest discover -v tests`; compared findings against real `curl -I` output of a site you own or a lab (e.g. your own localhost server, OWASP Juice Shop); cross-checked with securityheaders.com or Mozilla Observatory; checked MDN/RFC pages for each rule; edited samples to make tests fail and confirmed they did.

## 6. What did you change after reviewing the AI-generated work?
**[YOU MUST FILL IN with real changes, e.g. severities you disagreed with, extra rules, fixed bugs.]**

## 7. Which part can you confidently explain without AI assistance?
**[YOU MUST FILL IN honestly.]** Be ready for live verification: explain `parse_response`, `check_csp`'s nonce/unsafe-inline logic, and the HTTP-vs-HTTPS suppression, and be able to add a new rule (for example `Cross-Origin-Opener-Policy`) live.
