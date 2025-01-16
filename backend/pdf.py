from fpdf import FPDF
import pandas as pd

class PDF(FPDF):
    def header(self):
        # This is the header for all pages
        self.set_font('Helvetica', 'B', 14)
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

    def add_dict(self, data_dict):
        self.set_font("Helvetica", size=12)
        
        for key, value in data_dict.items():
            entry = f"{key}: {value}"
            self.cell(0, 10, entry, ln=True)

def createPDF(stats):
    # Create instance of PDF class
    pdf = PDF()

    # First page with headers
    pdf.add_page()
    # pdf.cell(0, 10, "Statistics", align='C', ln=1)
    # pdf.add_dict(stats)
    pdf.set_font("Helvetica", size = 12)
    pdf.cell(0, 10, 'Packet capture elapsed time: ' + str(stats['pcap_duration']) + 's', ln=True)
    pdf.cell(0, 10, 'Packet count: ' + str(stats['packets_count']), ln=True)
    pdf.cell(0, 10, 'Average packets per second: ' + str(stats['pps']), ln=True)
    pdf.cell(0, 10, 'Date and time of first packet: ' + str(stats['first_packet_time']), ln=True)
    pdf.cell(0, 10, 'Date and time of last packet: ' + str(stats['last_packet_time']), ln=True)

    # Image paths
    images = ['frontend/static/images/src.png', 'frontend/static/images/dst.png', 'frontend/static/images/sport.png', 'frontend/static/images/dport.png']

    # Coordinates for the grid placement
    x_list = [10, 110]  # X coordinates for two columns
    y_list = [80, 180]  # Y coordinates for two rows

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
    pdf.output("output/PCAP_Statistics.pdf")
