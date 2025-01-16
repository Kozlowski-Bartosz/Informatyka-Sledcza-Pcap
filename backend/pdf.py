from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        # This is the header for all pages
        self.set_font('Helvetica', 'B', 12)
        self.cell(0, 10, 'PCAP Statistics', 0, align='C')
        self.ln(10)

    def footer(self):
        # Footer that includes page number
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'{self.page_no()}', 0, align='C')

    def simple_table(self, header, data):
        # Set header font
        self.set_font('Helvetica', 'B', 12)
        # Draw header
        for col in header:
            self.cell(40, 10, col, border=1)
        self.ln()
        
        # Data font
        self.set_font('Helvetica', '', 12)
        # Draw data rows
        for row in data:
            for item in row:
                self.cell(40, 10, item, border=1)
            self.ln()

def createPDF():
    # Create instance of PDF class
    pdf = PDF()

    # First page with headers
    pdf.add_page()
    pdf.set_font("Helvetica", size = 12)
    pdf.cell(0, 10, "Statistics", align='C')

    # Adding second page for images
    pdf.add_page()
    pdf.cell(0, 10, "Graphs", align='C')

    # Image paths
    images = ['static/images/src.png', 'static/images/dst.png', 'static/images/sport.png', 'static/images/dport.png']

    # Coordinates for the grid placement
    x_list = [10, 110]  # X coordinates for two columns
    y_list = [50, 150]  # Y coordinates for two rows

    # Adding images in a grid 2x2
    for i, img in enumerate(images):
        pdf.image(img, x=x_list[i % 2], y=y_list[i // 2], w=90)

    pdf.add_page()

    # Sample header and data
    header = ['Header 1', 'Header 2', 'Header 3']
    data = [
        ['Row 1 Col 1', 'Row 1 Col 2', 'Row 1 Col 3'],
        ['Row 2 Col 1', 'Row 2 Col 2', 'Row 2 Col 3'],
        ['Row 3 Col 1', 'Row 3 Col 2', 'Row 3 Col 3']
    ]

    # Adding a simple table
    pdf.simple_table(header, data)

    # Save the PDF to a file
    pdf.output("static/PCAP_Statistics.pdf")
