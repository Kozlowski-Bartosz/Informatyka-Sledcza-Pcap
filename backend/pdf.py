from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 14)
        self.cell(0, 5, 'PCAP Statistics', 0, align='C')
        self.ln(10)


    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'{self.page_no()}', 0, align='C')


    def simple_table(self, header, data):
        self.set_font('Helvetica', 'B', 12)
        for col in header:
            self.cell(40, 10, col, border=1)
        self.ln()
        
        self.set_font('Helvetica', '', 12)
        for row in data:
            for item in row:
                self.cell(40, 10, item, border=1)
            self.ln()


    def add_dict_table(self, data, caption):
        self.set_font("Helvetica", size=12, style="B")
        self.cell(0, 10, caption, ln=True, align="C")

        headers = data[0].keys()
        col_width = 40
        table_width = col_width * len(headers)

        start_x = (self.w - table_width) / 2

        self.set_x(start_x)
        for header in headers:
            self.cell(col_width, 6, header, border=1, align="C")
        self.ln()

        self.set_font("Helvetica", size=10)
        for item in data:
            self.set_x(start_x)
            for value in item.values():
                self.cell(col_width, 6, str(value), border=1, align="C")
            self.ln()


def create_pdf(stats, src_ip, dst_ip, src_ports, dst_ports):
    pdf = PDF()
    pdf.add_page()
  
    pdf.set_font("Helvetica", size = 12)
    pdf.cell(0, 8, 'Packet capture elapsed time: ' + str(stats['pcap_duration']) + 's', ln=True)
    pdf.cell(0, 8, 'Packet count: ' + str(stats['packets_count']), ln=True)
    pdf.cell(0, 8, 'Average packets per second: ' + str(stats['pps']), ln=True)
    pdf.cell(0, 8, 'Date and time of first packet: ' + str(stats['first_packet_time']), ln=True)
    pdf.cell(0, 8, 'Date and time of last packet: ' + str(stats['last_packet_time']), ln=True)

    images = ['frontend/static/images/src.png', 'frontend/static/images/dst.png', 'frontend/static/images/sport.png', 'frontend/static/images/dport.png']

    x_list = [10, 110]
    y_list = [80, 180]
    for i, img in enumerate(images):
        pdf.image(img, x=x_list[i % 2], y=y_list[i // 2], w=90)

    pdf.add_page()

    pdf.add_dict_table(src_ip, "Source IPs")
    pdf.ln(10)
    pdf.add_dict_table(dst_ip, "Destination IPs")
    pdf.ln(10)
    pdf.add_dict_table(src_ports, "Source Ports Usage")
    pdf.ln(10)
    pdf.add_dict_table(dst_ports, "Destination Ports Usage")
    pdf.output("output/PCAP_Statistics.pdf")
