from flask import Blueprint, render_template, request, session, current_app, redirect, Response
from werkzeug.utils import secure_filename
from backend.pcap_reader import read_packets
from backend.pcap_reader import packets_to_df
from backend.pcap_reader import plot_pie_png

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


@main_bp.route('/src_pie.png')
def src_pie():
    pcap_file_path = session.get('uploaded_pcap_file_path', None)
    df = packets_to_df(pcap_file_path)
    buf = plot_pie_png(df, 'source', 'Top 5 source addresses')
    return Response(buf, mimetype='image/png')

@main_bp.route('/dst_pie.png')
def dst_pie():
    pcap_file_path = session.get('uploaded_pcap_file_path', None)
    df = packets_to_df(pcap_file_path)
    buf = plot_pie_png(df, 'destination', 'Top 5 destination addresses')
    return Response(buf, mimetype='image/png')


@main_bp.route('/stats')
def stats():
    return render_template('stats.html')


@main_bp.route('/extracted')
def extracted():
    return render_template('extracted.html')
