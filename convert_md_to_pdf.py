#!/usr/bin/env python3
"""
Convert markdown report to PDF and HTML
Simple markdown parser for clean export
"""
import os
import re

def remove_emojis(text):
    """Remove emoji and special Unicode characters"""
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF"
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "\U0001f926-\U0001f937"
        "\U00010000-\U0010ffff"
        "\u2640-\u2642"
        "\u2600-\u2B55"
        "\u200d"
        "\u23cf"
        "\u23e9"
        "\u231a"
        "\ufe0f"
        "\u3030"
        "]+"
        , flags=re.UNICODE)
    return emoji_pattern.sub(r'', text)

def read_markdown_file(file_path):
    """Read markdown file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

def markdown_to_html(md_content):
    """Convert markdown to clean HTML"""
    lines = md_content.split('\n')
    html_lines = ['<!DOCTYPE html>', '<html>', '<head>', '<meta charset="UTF-8">', '<title>MITRE ATT&CK Coverage Report</title>', '<style>']
    html_lines.append('''body { font-family: "Segoe UI", Arial, sans-serif; line-height: 1.6; color: #333; margin: 30px; max-width: 900px; }
h1 { font-size: 28px; font-weight: bold; margin-top: 30px; margin-bottom: 15px; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
h2 { font-size: 22px; font-weight: bold; margin-top: 25px; margin-bottom: 12px; color: #0078d4; }
h3 { font-size: 18px; font-weight: bold; margin-top: 15px; margin-bottom: 10px; }
table { border-collapse: collapse; width: 100%; margin: 15px 0; font-size: 13px; }
td, th { border: 1px solid #ddd; padding: 10px; text-align: left; }
th { background-color: #f3f3f3; font-weight: bold; }
tr:nth-child(even) { background-color: #f9f9f9; }
code { background-color: #f4f4f4; padding: 2px 6px; font-family: "Courier New", monospace; border-radius: 3px; }
pre { background-color: #f4f4f4; padding: 12px; overflow-x: auto; border-radius: 4px; border-left: 3px solid #0078d4; }
blockquote { border-left: 4px solid #0078d4; margin-left: 0; padding-left: 15px; color: #555; }
ul, ol { margin: 12px 0; padding-left: 30px; }
li { margin: 6px 0; }
strong { font-weight: bold; color: #000; }
em { font-style: italic; }
.page-break { page-break-after: always; margin: 20px 0; border-top: 1px dashed #ccc; padding-top: 20px; }
''')
    html_lines.append('</style></head><body>')
    
    in_code_block = False
    code_content = []
    
    for i, line in enumerate(lines):
        line_stripped = line.rstrip()
        
        # Handle code blocks
        if line_stripped.startswith('```'):
            if in_code_block:
                html_lines.append('<pre><code>' + '\n'.join(code_content) + '</code></pre>')
                code_content = []
                in_code_block = False
            else:
                in_code_block = True
            continue
        
        if in_code_block:
            code_content.append(line_stripped)
            continue
        
        # Skip empty lines but add spacing
        if not line_stripped:
            html_lines.append('')
            continue
        
        # Headers
        if line_stripped.startswith('# '):
            text = line_stripped.lstrip('# ')
            html_lines.append(f'<h1>{text}</h1>')
        elif line_stripped.startswith('## '):
            text = line_stripped.lstrip('## ')
            html_lines.append(f'<h2>{text}</h2>')
        elif line_stripped.startswith('### '):
            text = line_stripped.lstrip('### ')
            html_lines.append(f'<h3>{text}</h3>')
        elif line_stripped.startswith('#### '):
            text = line_stripped.lstrip('#### ')
            html_lines.append(f'<h4>{text}</h4>')
        # Tables
        elif line_stripped.startswith('| '):
            # Parse table row
            cells = [cell.strip() for cell in line_stripped.split('|')[1:-1]]
            if all(cell in ['-' * len(cell), ':', '-' * (len(cell)-2), '-' * (len(cell)-2) + ':', ':' + '-' * (len(cell)-2)] for cell in cells):
                # Separator row, skip
                continue
            else:
                row_html = '<tr>' + ''.join(f'<td>{cell}</td>' for cell in cells) + '</tr>'
                if i == 0 or (i > 0 and lines[i-1].rstrip().startswith('| ')):
                    # Check if this is a header (look for separator on next line)
                    if i+1 < len(lines) and lines[i+1].rstrip().startswith('| ') and all(c in '-|:' for c in lines[i+1].rstrip()):
                        row_html = '<tr>' + ''.join(f'<th>{cell}</th>' for cell in cells) + '</tr>'
                        html_lines.append('<table>')
                        html_lines.append(row_html)
                    elif not html_lines[-1].startswith('<table'):
                        html_lines.append('<table>')
                        html_lines.append(row_html)
                    else:
                        html_lines.append(row_html)
                elif html_lines[-1].startswith('<table'):
                    html_lines.append(row_html)
                elif any(tag in html_lines[-1] for tag in ['<tr>', '<th>', '<td>']):
                    html_lines.append(row_html)
                else:
                    html_lines.append('<table>')
                    html_lines.append(row_html)
        # Check for table closing
        elif not line_stripped.startswith('| ') and html_lines and any(tag in html_lines[-1] for tag in ['<tr>', '<th>', '<td>', '<table']):
            if '</table>' not in html_lines[-1]:
                html_lines.append('</table>')
        # Quotes
        elif line_stripped.startswith('> '):
            text = line_stripped.lstrip('> ')
            html_lines.append(f'<blockquote>{text}</blockquote>')
        # Bullet lists
        elif line_stripped.startswith('- '):
            text = line_stripped.lstrip('- ')
            html_lines.append(f'<ul><li>{text}</li></ul>')
        elif line_stripped.startswith('* '):
            text = line_stripped.lstrip('* ')
            html_lines.append(f'<ul><li>{text}</li></ul>')
        # Regular text with formatting
        else:
            text = line_stripped
            # Apply inline formatting
            text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
            text = re.sub(r'__(.*?)__', r'<strong>\1</strong>', text)
            text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
            text = re.sub(r'_(.*?)_', r'<em>\1</em>', text)
            text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
            html_lines.append(f'<p>{text}</p>')
    
    # Close any open table
    if any(tag in html_lines[-1] for tag in ['<tr>', '<th>', '<td>']):
        html_lines.append('</table>')
    
    html_lines.append('</body></html>')
    return '\n'.join(html_lines)

def markdown_to_pdf_via_html(md_file, pdf_file, html_file):
    """Convert markdown to HTML and optionally to PDF"""
    md_content = read_markdown_file(md_file)
    md_content = remove_emojis(md_content)
    
    # Generate HTML
    html_content = markdown_to_html(md_content)
    
    # Save HTML
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"✅ HTML version saved: {html_file}")
    
    # Try to convert HTML to PDF
    try:
        from weasyprint import HTML
        HTML(html_file).write_pdf(pdf_file)
        print(f"✅ PDF generated successfully: {pdf_file}")
        return True
    except ImportError:
        pass
    except Exception as e:
        print(f"⚠ WeasyPrint conversion failed: {e}")
    
    try:
        import pdfkit
        pdfkit.from_file(html_file, pdf_file)
        print(f"✅ PDF generated successfully: {pdf_file}")
        return True
    except Exception as e:
        pass
    
    print(f"\nℹ HTML file saved successfully!")
    print(f"To generate PDF, open the HTML file and use browser's Print to PDF feature:")
    print(f"1. Open {html_file} in your browser")
    print(f"2. Press Ctrl+P (or Cmd+P)")
    print(f"3. Select 'Save as PDF' and save to {pdf_file}")

if __name__ == "__main__":
    md_path = "reports/MITRE_ATT_CK_Coverage_Report_20260418.md"
    pdf_path = "reports/MITRE_ATT_CK_Coverage_Report_20260418.pdf"
    html_path = "reports/MITRE_ATT_CK_Coverage_Report_20260418.html"
    
    if not os.path.exists(md_path):
        print(f"❌ File not found: {md_path}")
        exit(1)
    
    markdown_to_pdf_via_html(md_path, pdf_path, html_path)
