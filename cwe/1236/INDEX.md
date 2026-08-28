# CWE-1236: Improper Neutralization of Formula Elements in a CSV File

## LLM Guidance

Formula Injection (also known as CSV Injection or Excel Injection) occurs when untrusted data containing formula metacharacters (=, +, -, @, tab, carriage return) is exported to spreadsheet files (CSV, Excel, etc.) without proper sanitization. Spreadsheet applications interpret these characters as formula directives, executing embedded commands.

## Key Principles

- Treat all spreadsheet exports as potential code execution vectors requiring input sanitization
- Neutralize formula metacharacters (=, +, -, @) at export time before writing to cells
- Apply defence-in-depth by combining prefix detection, sanitization, and CSV-safe encoding
- Validate all untrusted data sources (user input, databases, external files) before export
- Use established libraries that handle formula injection protection automatically
- Neutralize the value rather than stripping it: prefixing a leading `=`, `+`, `-`, `@`, tab or carriage return with an apostrophe keeps the data intact, while removing the character silently changes a legitimate value such as a negative number
- Quoting is not neutralization - a spreadsheet parses the formula after removing the quotes, so a CSV-quoted cell still executes
- Apply it at export time, to every untrusted field including ones that look numeric, and remember the finding applies to `.xlsx` and to clipboard exports as well as `.csv`

## Remediation Steps

- Identify all spreadsheet export functionality and trace untrusted data flows to export points
- Prepend single quote (') to any cell value starting with =, +, -, @ to force literal interpretation
- Remove or escape tab and carriage return characters from all cell content
- Implement CSV-safe encoding libraries designed to prevent formula injection
- Test exports by opening files in Excel/LibreOffice to verify formulas don't execute
- Add automated tests that attempt injection with malicious formulas to validate protection
