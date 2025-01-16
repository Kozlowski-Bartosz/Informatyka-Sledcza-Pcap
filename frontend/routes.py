from flask import Blueprint, render_template, request, session, current_app, redirect, Response, send_file, flash
from werkzeug.utils import secure_filename
from backend.pcap_reader import (
    read_packets,
    packets_to_df,
    plot_pie_png_file,
    seek_https_requests,
    pcap_statistics,
    info_tables
)
from backend.extractor import (
    extract_images_from_http,
    extract_authentication_data_from_http,
    extract_ftp_credentials,
    extract_file_from_ftp
)
from backend.pdf import (
    createPDF
)

import os
import logging

logger = logging.getLogger(__name__)

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    current_app.logger.debug("Index route")
    return render_template('index.html')


@main_bp.route('/upload', methods=['POST'])
def uploadFile():
    if request.method == 'POST':
      # upload file flask
        f = request.files.get('file')

        # Extracting uploaded file name
        data_filename = secure_filename(f.filename)

        if not data_filename.lower().endswith('.pcap'):
            flash("That's not a .pcap!")
            return redirect('/')

        f.save(os.path.join(
            current_app.config['UPLOAD_FOLDER'], data_filename))

        session['uploaded_pcap_file_path'] = os.path.join(
            current_app.config['UPLOAD_FOLDER'], data_filename)

        return redirect('/results')
    return render_template("index.html")


@main_bp.route('/results', methods=['GET'])
def results():
    current_app.logger.debug("Results route")
    pcap_file_path = session.get('uploaded_pcap_file_path', None)
    data = read_packets(pcap_file_path)
    return render_template('results.html', packet_data=data)


@main_bp.route('/stats')
def stats():
    current_app.logger.debug("Stats route")
    pcap_file_path = session.get('uploaded_pcap_file_path', None)
    df = packets_to_df(pcap_file_path)
    stats = pcap_statistics(df)
    plot_pie_png_file(df, 'source', 'Top source addresses', 'src.png')
    plot_pie_png_file(df, 'destination', 'Top destination addresses', 'dst.png')
    plot_pie_png_file(df, 'src_port', 'Top source ports', 'sport.png')
    plot_pie_png_file(df, 'dst_port', 'Top destination ports', 'dport.png')
    src_ip, dst_ip, src_ports, dst_ports = info_tables(df)
    createPDF(stats, src_ip, dst_ip, src_ports, dst_ports)
    return render_template('stats.html', pcap_stats = stats, src_ip_list = src_ip, dst_ip_list = dst_ip, src_port_list = src_ports, dst_port_list = dst_ports)


@main_bp.route('/extracted')
def extracted():
    current_app.logger.debug("Extracted route")
    pcap_file_path = session.get('uploaded_pcap_file_path', None)
    http_request_data = seek_https_requests(pcap_file_path)
    images = extract_images_from_http(pcap_file_path)
    cred = extract_authentication_data_from_http(pcap_file_path)
    ftp_cred = extract_ftp_credentials(pcap_file_path)
    ftp_files = extract_file_from_ftp(pcap_file_path)
    return render_template('extracted.html', url_list=http_request_data, image_filenames=images, cred_list=cred, ftp_cred_list=ftp_cred, ftp_files_list=ftp_files)


# Required to import images from outside the static folder
@main_bp.route('/output/images/<path:filename>')
def output_images(filename):
    path = os.path.abspath(f"output/images/{filename}")
    if os.path.exists(path):
        response = send_file(path)
    return response

@main_bp.route('/save', methods=['POST'])
def save_visible_rows():
    data = request.form['data']
    with open('output/results/filtered_packets.txt', 'w') as file:
        file.write(data)
    return 'OK'