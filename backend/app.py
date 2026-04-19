import threading, time, io, struct, os, uuid
from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_socketio import SocketIO
from flask_cors import CORS
import packet_engine

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
                    logger=False, engineio_logger=False,
                    ping_timeout=60, ping_interval=25)

_last_frame = None
_last_layers = None
_state_lock = threading.Lock()
_current_build_id = None
_pause_event = threading.Event()
_pause_event.set()


def set_current_build(build_id):
    global _current_build_id
    with _state_lock:
        _current_build_id = build_id
        _pause_event.set()


def is_current_build(build_id):
    with _state_lock:
        return _current_build_id == build_id


def cancel_current_build(build_id=None):
    global _current_build_id
    with _state_lock:
        if build_id is None or _current_build_id == build_id:
            _current_build_id = None
            _pause_event.set()
            return True
    return False


def wait_until_resumed(build_id):
    while True:
        if not is_current_build(build_id):
            return False
        if _pause_event.is_set():
            return True
        _pause_event.wait(0.1)


def pause_aware_sleep(seconds, build_id):
    remaining = max(0, float(seconds))
    while remaining > 0:
        if not wait_until_resumed(build_id):
            return False
        step = min(0.05, remaining)
        time.sleep(step)
        remaining -= step
    return is_current_build(build_id)


def remember_packet(layers, raw_frame):
    global _last_layers, _last_frame
    with _state_lock:
        _last_layers = [dict(layer) for layer in layers]
        _last_frame = raw_frame


def get_last_layers():
    with _state_lock:
        if not _last_layers:
            return None
        return [dict(layer) for layer in _last_layers]


def make_decap_event(layer, build_id):
    event = dict(layer)
    layer_name = event.get('layer_name', 'Layer')
    protocol = event.get('protocol', 'header')
    header_size = event.get('header_size', 0)
    fields = dict(event.get('fields', {}))

    if event.get('layer_number') == 7:
        action = 'Deliver original application data'
        description = (
            'Decapsulation reaches the Application layer. The receiving app '
            'gets the original payload after every lower-layer header has '
            'been interpreted and removed.'
        )
    else:
        action = f'Remove {protocol} header ({header_size} bytes)'
        description = (
            f'Decapsulation at the {layer_name} layer reads the {protocol} '
            'header, uses its fields, strips that header, and passes the '
            'remaining payload up to the next layer.'
        )
        if event.get('layer_number') == 3 and event.get('corrupt'):
            description += (
                ' The IP checksum is invalid here, so a real receiver would '
                'drop the packet instead of delivering it upward.'
            )

    fields = {
        'Decapsulation step': action,
        'Next direction': 'Up the stack',
        **fields,
    }
    event['build_id'] = build_id
    event['direction'] = 'decap'
    event['description'] = description
    event['fields'] = fields
    return event


@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response


@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('../frontend', path)


@app.route('/api/control', methods=['POST', 'OPTIONS'])
def control():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json(force=True)
    action = str(data.get('action', '')).lower()
    build_id = data.get('build_id')

    if action == 'pause':
        if build_id is None or is_current_build(build_id):
            _pause_event.clear()
            return jsonify({'status': 'paused'})
        return jsonify({'status': 'ignored'})

    if action == 'resume':
        if build_id is None or is_current_build(build_id):
            _pause_event.set()
            return jsonify({'status': 'resumed'})
        return jsonify({'status': 'ignored'})

    if action == 'cancel':
        cancelled = cancel_current_build(build_id)
        return jsonify({'status': 'cancelled' if cancelled else 'ignored'})

    return jsonify({'error': 'Unknown control action'}), 400


@app.route('/api/build', methods=['POST', 'OPTIONS'])
def build():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    data = request.get_json(force=True)
    message = data.get('message', 'Hello, World!')
    protocol = data.get('protocol', 'tcp')
    src_ip = data.get('src_ip', '192.168.0.1')
    dst_ip = data.get('dst_ip', '192.168.0.2')
    corrupt = bool(data.get('corrupt', False))
    speed = max(0.3, min(2.0, float(data.get('speed', 0.9))))
    build_id = str(data.get('build_id') or uuid.uuid4().hex)
    set_current_build(build_id)

    def run():
        global _last_frame
        try:
            layers, raw_frame = packet_engine.build_packet(
                message, protocol, src_ip, dst_ip, corrupt)
            if not is_current_build(build_id):
                return
            remember_packet(layers, raw_frame)
            for index, layer in enumerate(layers):
                if not wait_until_resumed(build_id):
                    return
                event = dict(layer)
                event['build_id'] = build_id
                event['direction'] = 'encap'
                socketio.emit('layer_event', event)
                if index < len(layers) - 1 and not pause_aware_sleep(speed, build_id):
                    return
            if not is_current_build(build_id):
                return
            socketio.emit('build_complete', {
                'build_id': build_id,
                'total_bytes': len(raw_frame),
                'layers': len(layers)
            })
        except Exception as e:
            if is_current_build(build_id):
                socketio.emit('build_error', {
                    'build_id': build_id,
                    'message': str(e)
                })

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'status': 'started', 'build_id': build_id})


@app.route('/api/decapsulate', methods=['POST', 'OPTIONS'])
def decapsulate():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    layers = get_last_layers()
    if not layers:
        return jsonify({'error': 'No completed packet to decapsulate'}), 400

    data = request.get_json(force=True)
    speed = max(0.3, min(2.0, float(data.get('speed', 0.9))))
    build_id = str(data.get('build_id') or uuid.uuid4().hex)
    set_current_build(build_id)
    decap_layers = list(reversed(layers))

    def run():
        try:
            for index, layer in enumerate(decap_layers):
                if not wait_until_resumed(build_id):
                    return
                socketio.emit('decap_layer_event',
                              make_decap_event(layer, build_id))
                if index < len(decap_layers) - 1 and not pause_aware_sleep(speed, build_id):
                    return
            if not is_current_build(build_id):
                return
            socketio.emit('decap_complete', {
                'build_id': build_id,
                'layers': len(decap_layers)
            })
        except Exception as e:
            if is_current_build(build_id):
                socketio.emit('build_error', {
                    'build_id': build_id,
                    'message': str(e)
                })

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'status': 'started', 'build_id': build_id})


@app.route('/api/export-pcap')
def export_pcap():
    global _last_frame
    if not _last_frame:
        return jsonify({'error': 'No packet yet'}), 400
    buf = io.BytesIO()
    buf.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    ts = int(time.time())
    buf.write(struct.pack('<IIII', ts, 0, len(_last_frame), len(_last_frame)))
    buf.write(_last_frame)
    buf.seek(0)
    return send_file(buf, mimetype='application/octet-stream',
                     as_attachment=True, download_name='capture.pcap')


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    print("\n  OSI Visualizer ? http://localhost:5000\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False,
                 allow_unsafe_werkzeug=True)
