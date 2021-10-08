from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import sys, os
sys.path.append(os.getcwd())
from inference_service import AlexNetInference

app = Flask(__name__)
alexnet = AlexNetInference()


@app.route("/")
def index():
    return "Hello from inside Mystikos!"

@app.route("/evaluate", methods=["POST"])
def evaluate_sample():
    if request.method == "POST":
        f = request.files["image"]
        f.save(secure_filename(f.filename))
        print(f"file:{f.filename}")
        output = alexnet.evaluate_formatted(f.filename)
        return f"file uploaded successfully.\n{output}"


if __name__ == "__main__":
    print("the secret obtained through ssr: ");
    with open("/mykey", 'rb') as fin:
        print(fin.read())
    app.run(debug=True, host="0.0.0.0", port="8000", use_reloader=False)
