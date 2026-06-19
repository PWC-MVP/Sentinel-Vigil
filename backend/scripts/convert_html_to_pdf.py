import os
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from html.parser import HTMLParser
from xml.sax.saxutils import escape

class PlatypusParser(HTMLParser):
    """Convert HTML items to ReportLab Platypus elements."""
    def __init__(self):
        super().__init__()
        self.styles = getSampleStyleSheet()
        self.elements = []
        self.current_text = ""
        self.tag_stack = []
        self.table_data = []
        self.current_row = []
        
    def clean_text(self, text):
        """Strip emojis and escape XML special characters for ReportLab."""
        if not text:
            return ""
        # Strip non-BMP characters (emojis)
        text = "".join(c for c in text if ord(c) < 65536)
        # Escape for XML/ReportLab Paragraph
        return escape(text)

    def handle_starttag(self, tag, attrs):
        self.tag_stack.append(tag)
        # Block-level tags that should clear current text to start fresh
        if tag in ('h1', 'h2', 'h3', 'h4', 'p', 'li', 'td', 'th', 'div', 'tr', 'table'):
            # If there was text in a generic container (like div), flush it first?
            # For simplicity, we just clear for new blocks
            self.current_text = ""
        elif tag == 'br':
            self.current_text += "<br/>"

    def handle_endtag(self, tag):
        text = self.clean_text(self.current_text.strip())
        
        if tag == 'h1':
            self.elements.append(Paragraph(f"<b>{text}</b>", self.styles['Heading1']))
            self.elements.append(Spacer(1, 0.2*inch))
            self.current_text = ""
        elif tag == 'h2':
            self.elements.append(Paragraph(f"<b>{text}</b>", self.styles['Heading2']))
            self.elements.append(Spacer(1, 0.15*inch))
            self.current_text = ""
        elif tag == 'h3':
            self.elements.append(Paragraph(text, self.styles['Heading3']))
            self.elements.append(Spacer(1, 0.1*inch))
            self.current_text = ""
        elif tag == 'h4':
            self.elements.append(Paragraph(text, self.styles['Heading4']))
            self.elements.append(Spacer(1, 0.08*inch))
            self.current_text = ""
        elif tag in ('p', 'div'):
            if text and len(text) > 1:
                self.elements.append(Paragraph(text, self.styles['Normal']))
                self.elements.append(Spacer(1, 0.1*inch))
            self.current_text = ""
        elif tag == 'li':
            if text:
                self.elements.append(Paragraph(f"&bull; {text}", self.styles['Normal']))
            self.current_text = ""
        elif tag == 'td' or tag == 'th':
            self.current_row.append(text)
            self.current_text = ""
        elif tag == 'tr':
            if self.current_row:
                self.table_data.append(self.current_row)
            self.current_row = []
        elif tag == 'table':
            if self.table_data:
                clean_data = [r for r in self.table_data if any(str(cell).strip() for cell in r)]
                if clean_data:
                    max_cols = max(len(r) for r in clean_data)
                    for r in clean_data:
                        while len(r) < max_cols:
                            r.append("")
                    
                    t = Table(clean_data, colWidths=[1.3*inch]*max_cols)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f3f3')),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('WORDWRAP', (0, 0), (-1, -1)),
                    ]))
                    self.elements.append(t)
                    self.elements.append(Spacer(1, 0.2*inch))
            self.table_data = []
            self.current_row = []

        if self.tag_stack:
            self.tag_stack.pop()

    def handle_data(self, data):
        if data.strip():
            # Don't escape here, we escape in handle_endtag/clean_text
            self.current_text += data

def html_to_pdf(html_file, pdf_file):
    """Convert HTML to PDF using proper parsing."""
    try:
        if not os.path.exists(html_file):
            raise FileNotFoundError(f"HTML file not found: {html_file}")
            
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
            
        doc = SimpleDocTemplate(
            pdf_file, 
            pagesize=letter,
            rightMargin=0.5*inch, 
            leftMargin=0.5*inch, 
            topMargin=0.5*inch, 
            bottomMargin=0.5*inch
        )
        
        parser = PlatypusParser()
        parser.feed(html_content)
        
        # If no structured elements found, try to capture all text
        if not parser.elements:
            raw_text = re.sub('<[^<]+?>', '', html_content)
            clean_raw = parser.clean_text(raw_text.strip())
            if clean_raw:
                parser.elements.append(Paragraph("Report Content (Extraction):", parser.styles['Heading2']))
                # Split into chunks to avoid Paragraph limits
                for chunk in [clean_raw[i:i+4000] for i in range(0, len(clean_raw), 4000)]:
                    parser.elements.append(Paragraph(chunk, parser.styles['Normal']))
            else:
                parser.elements.append(Paragraph("Note: No readable text found in report.", parser.styles['Normal']))
        
        doc.build(parser.elements)
        return True
    except Exception as e:
        print(f"CRITICAL Error in html_to_pdf: {e}")
        # Last resort: minimal PDF
        try:
            doc = SimpleDocTemplate(pdf_file)
            doc.build([Paragraph(f"Internal PDF Generation Error: {escape(str(e))}", getSampleStyleSheet()['Normal'])])
        except:
            pass
        raise e

if __name__ == "__main__":
    import sys
    # Example usage: python convert_html_to_pdf.py input.html output.pdf
    if len(sys.argv) > 2:
        html_to_pdf(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python convert_html_to_pdf.py <input_html> <output_pdf>")
