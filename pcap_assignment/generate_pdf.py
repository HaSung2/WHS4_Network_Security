import os
import re
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Define output path
PDF_OUTPUT_PATH = "/Users/song/tesk/WHS/04_네트워크보안/pcap_assignment/[WHS][PCAP Programming] 37반 송하성(0958).pdf"
MD_INPUT_PATH = "/Users/song/tesk/WHS/04_네트워크보안/pcap_assignment/report.md"
FONT_PATH = "/System/Library/Fonts/Supplemental/AppleGothic.ttf"

def register_korean_font():
    """Register the macOS AppleGothic font to support Korean text."""
    if os.path.exists(FONT_PATH):
        pdfmetrics.registerFont(TTFont('AppleGothic', FONT_PATH))
        print(f"[+] Successfully registered Korean font from {FONT_PATH}")
        return 'AppleGothic'
    else:
        print("[-] AppleGothic font not found at the default supplemental path.")
        # Try fallback system path
        fallback = "/System/Library/Fonts/AppleSDGothicNeo.ttc"
        if os.path.exists(fallback):
            pdfmetrics.registerFont(TTFont('AppleGothic', fallback))
            print(f"[+] Successfully registered Korean font from fallback: {fallback}")
            return 'AppleGothic'
        else:
            print("[-] No suitable Korean font found. Using default Helvetica (Korean text might not render).")
            return 'Helvetica'

def parse_markdown(md_text):
    """Simple block-level markdown parser."""
    # Clean up LaTeX formula for ReportLab
    md_text = md_text.replace(
        r'$$\text{Payload Length} = \text{iph\_len} - \text{IP Header Length} - \text{TCP Header Length}$$',
        'Payload Length = iph_len - IP Header Length - TCP Header Length'
    )
    
    blocks = []
    lines = md_text.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Skip empty lines
        if not line.strip():
            i += 1
            continue
            
        # Code block
        if line.strip().startswith('```'):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            blocks.append(('code', '\n'.join(code_lines)))
            i += 1
            continue
            
        # Horizontal rule
        if line.strip() == '---':
            blocks.append(('hr', ''))
            i += 1
            continue
            
        # Headings
        if line.startswith('# '):
            blocks.append(('h1', line[2:].strip()))
            i += 1
            continue
        if line.startswith('## '):
            blocks.append(('h2', line[3:].strip()))
            i += 1
            continue
        if line.startswith('### '):
            blocks.append(('h3', line[4:].strip()))
            i += 1
            continue
            
        # Bullet list items
        if line.strip().startswith('* ') or line.strip().startswith('- '):
            content = line.strip()[2:].strip()
            blocks.append(('bullet', content))
            i += 1
            continue
            
        # Normal paragraph (accumulate contiguous text lines)
        para_lines = []
        while i < len(lines) and lines[i].strip():
            curr_line = lines[i].strip()
            if (curr_line.startswith('#') or 
                curr_line.startswith('```') or 
                curr_line.startswith('* ') or 
                curr_line.startswith('- ') or 
                curr_line == '---'):
                break
            para_lines.append(curr_line)
            i += 1
        
        if para_lines:
            blocks.append(('paragraph', ' '.join(para_lines)))
            
    return blocks

def process_inline_formatting(text, font_name):
    """Convert Markdown inline formatting (bold, links, code) to HTML-like tags supported by ReportLab."""
    # Escape HTML special chars first
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    
    # Convert bold: **text** -> <b>text</b>
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    
    # Convert inline code: `code` -> font color/type
    text = re.sub(r'`(.*?)`', rf'<font face="{font_name}" color="#A01010" size="9.5"><code>\1</code></font>', text)
    
    # Convert links: [text](url) -> <a> link
    text = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2" color="#0969DA"><u>\1</u></a>', text)
    
    return text

def build_pdf(font_name):
    """Build the styled PDF report from report.md."""
    print(f"[*] Reading markdown file: {MD_INPUT_PATH}")
    with open(MD_INPUT_PATH, 'r', encoding='utf-8') as f:
        md_text = f.read()
        
    blocks = parse_markdown(md_text)
    
    # Page settings: A4, 20mm margins
    doc = SimpleDocTemplate(
        PDF_OUTPUT_PATH,
        pagesize=A4,
        leftMargin=20*mm,
        rightMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles using our registered Korean font
    styles.add(ParagraphStyle(
        name='MainTitle',
        fontName=font_name,
        fontSize=24,
        leading=30,
        textColor=HexColor('#0F766E'),  # Primary brand color (Deep Teal)
        spaceAfter=15,
        alignment=1  # Centered
    ))
    
    styles.add(ParagraphStyle(
        name='DocHeader',
        fontName=font_name,
        fontSize=10,
        leading=14,
        textColor=HexColor('#475569'),  # Slate grey
        spaceAfter=4
    ))
    
    styles.add(ParagraphStyle(
        name='CustomH1',
        fontName=font_name,
        fontSize=16,
        leading=22,
        textColor=HexColor('#0F766E'),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name='CustomH2',
        fontName=font_name,
        fontSize=12,
        leading=17,
        textColor=HexColor('#0D9488'),  # Medium Teal
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name='CustomH3',
        fontName=font_name,
        fontSize=10,
        leading=14,
        textColor=HexColor('#1E293B'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name='CustomBody',
        fontName=font_name,
        fontSize=9.5,
        leading=14.5,
        textColor=HexColor('#1E293B'),
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name='CustomBullet',
        fontName=font_name,
        fontSize=9.5,
        leading=14.5,
        textColor=HexColor('#1E293B'),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    ))

    code_style = ParagraphStyle(
        name='CodeStyle',
        fontName=font_name,
        fontSize=8,
        leading=11,
        textColor=HexColor('#24292F')
    )

    story = []
    
    # Check if first block is title, pull it for specialized layout
    title_text = "PCAP Programming 과제 보고서"
    for b_type, b_content in blocks:
        if b_type == 'h1' and 'PCAP Programming' in b_content:
            title_text = b_content
            break
            
    # Add cover metadata block
    # Course details, Student name, etc.
    story.append(Paragraph(title_text, styles['MainTitle']))
    story.append(Spacer(1, 5*mm))
    
    # Metadata card as a styled table
    meta_data = [
        [Paragraph("<b>교육과정:</b> 화이트햇 스쿨 4기 (37반)", styles['DocHeader']), 
         Paragraph("<b>제출일자:</b> 2026년 07월 05일", styles['DocHeader'])],
        [Paragraph("<b>제출자:</b> 송하성 (0958)", styles['DocHeader']), 
         Paragraph("<b>GitHub:</b> <a href='https://github.com/HaSung2/WHS4_Network_Security' color='#0969DA'><u>HaSung2/WHS4_Network_Security</u></a>", styles['DocHeader'])]
    ]
    meta_table = Table(meta_data, colWidths=[240, 240])
    meta_table.setStyle(TableStyle([
        ('LINEBELOW', (0,-1), (-1,-1), 1, HexColor('#CBD5E1')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6*mm))
    
    # Process blocks
    for b_type, b_content in blocks:
        # If it was the main title block, we already handled it
        if b_type == 'h1' and 'PCAP Programming' in b_content:
            continue
            
        if b_type == 'h1':
            formatted_text = process_inline_formatting(b_content, font_name)
            story.append(Paragraph(formatted_text, styles['CustomH1']))
            story.append(Spacer(1, 2*mm))
            
        elif b_type == 'h2':
            formatted_text = process_inline_formatting(b_content, font_name)
            story.append(Paragraph(formatted_text, styles['CustomH2']))
            story.append(Spacer(1, 1.5*mm))
            
        elif b_type == 'h3':
            formatted_text = process_inline_formatting(b_content, font_name)
            story.append(Paragraph(formatted_text, styles['CustomH3']))
            story.append(Spacer(1, 1*mm))
            
        elif b_type == 'paragraph':
            # Check for header block that is metadata and skip since we did it above
            if b_content.startswith('과정명:') or b_content.startswith('소속:') or b_content.startswith('이름:'):
                continue
            formatted_text = process_inline_formatting(b_content, font_name)
            story.append(Paragraph(formatted_text, styles['CustomBody']))
            
        elif b_type == 'bullet':
            formatted_text = process_inline_formatting(b_content, font_name)
            # Add bullet symbol
            bullet_html = f"&bull; {formatted_text}"
            story.append(Paragraph(bullet_html, styles['CustomBullet']))
            
        elif b_type == 'hr':
            # Add a visual divider line
            divider_data = [['']]
            divider = Table(divider_data, colWidths=[480])
            divider.setStyle(TableStyle([
                ('LINEABOVE', (0,0), (-1,-1), 0.5, HexColor('#E2E8F0')),
                ('BOTTOMPADDING', (0,0), (-1,-1), 10),
                ('TOPPADDING', (0,0), (-1,-1), 10),
            ]))
            story.append(divider)
            
        elif b_type == 'code':
            # Split code block by newline to allow page splitting between lines
            code_lines = b_content.split('\n')
            table_data = []
            for line in code_lines:
                display_line = line if line else ' '
                escaped_line = display_line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                table_data.append([Preformatted(escaped_line, code_style)])
                
            code_table = Table(table_data, colWidths=[480])
            code_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), HexColor('#F8FAFC')),
                ('PADDING', (0,0), (-1,-1), 1.5),  # Thin padding per line
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
                ('TOPPADDING', (0,0), (0,0), 6),     # Top padding for first line
                ('BOTTOMPADDING', (0,-1), (0,-1), 6), # Bottom padding for last line
                ('BOX', (0,0), (-1,-1), 0.5, HexColor('#E2E8F0')),
            ]))
            story.append(Spacer(1, 2*mm))
            story.append(code_table)
            story.append(Spacer(1, 4*mm))

    print(f"[*] Building PDF document: {PDF_OUTPUT_PATH}")
    doc.build(story)
    print("[+] PDF build completed successfully!")

if __name__ == "__main__":
    font = register_korean_font()
    build_pdf(font)
