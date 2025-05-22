import io
import threading
import time
from flask import Flask, Response, render_template_string
from PIL import ImageGrab

app = Flask(__name__)

HTML = """
<!doctype html>
<title>Live Screen Share</title>
<h2>Live Screen Share</h2>
<img src="/stream" style="width:90vw; border:2px solid #333;">
"""

def capture_screen():
    img = ImageGrab.grab()
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=70)
    return buf.getvalue()

def generate_frames():
    while True:
        frame = capture_screen()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        time.sleep(0.1)  # ~10 FPS

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/stream')
def stream():
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

if __name__ == '__main__':
    print("Starting live screen share. Open http://localhost:5000 in your browser.")
    app.run(host='0.0.0.0', port=5000, threaded=True) 