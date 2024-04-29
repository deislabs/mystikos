from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import sys, os
sys.path.append(os.getcwd())
from inference_service import AlexNetInference
from Crypto.Cipher import AES
import io
import pycurl
import time
from io import BytesIO

app = Flask(__name__)

iv = bytes(16)

@app.route("/")
def index():
    return "Hello from inside Mystikos!"

@app.route("/evaluate", methods=["POST"])
def evaluate_sample():
    if request.method == "POST":
        f = request.files["image"]
        secure_name = secure_filename(f.filename)
        f.save(secure_name)
        name = secure_name

        # Check if the file name ends with ".encrypted".
        # If yes, decrypt the file with the image key we obtained through SSR.
        paths = os.path.splitext(secure_name)
        if paths[-1]==".encrypted":
            name = paths[0]
            with open(secure_name, 'rb') as fin:
                cipher_text = fin.read()
                image_decypt = AES.new(image_key, AES.MODE_CBC, iv)
                plain_text = image_decypt.decrypt(cipher_text)
                with open(name, 'wb') as fout:
                    fout.write(plain_text)
                    print(f"Image file decrypted to:{name}")
                    time.sleep(1)

        output = alexnet.evaluate_formatted(name)
        return f"file inferenced successfully.\n{output}"

def download_and_decrypt(url, path, key, max_retries=3):
    # enumerate 
    for i in enumerate(range(max_retries)):
        try:
            output = io.BytesIO()
            cl = pycurl.Curl()
            cl.setopt(cl.URL, url)
            #cl.setopt(pycurl.VERBOSE, 1)
            cl.setopt(pycurl.FOLLOWLOCATION, 1)
            cl.setopt(pycurl.WRITEFUNCTION, output.write)
            cl.perform()
            cl.close()
            if output.getvalue():
                # aes_obj.decrypt() expects input to be a multiple of 16 in length
                # because AES encrypts in blocksize of 16 bytes.
                if len(output.getvalue()) % 16 == 0:
                    # Output is as expected, continue with the decryption
                    break
                else:
                    # Output is not a multiple of 16, print out debug information and retry
                    print(f"Try {i+1}: Retrieved value: {output.getvalue()}")
                    print(f"Try {i+1}: Retrieved value length {len(output.getvalue())} is not a multiple of 16.")
                    continue
        except pycurl.error as e:
            if i == max_retries - 1:  # If this was the last attempt, re-raise the exception
                raise
            else:
                print(f"Attempt {i+1} failed with error: {e}. Retrying in {2 ** i} seconds...")
                time.sleep(2 ** i)  # Exponential backoff (in seconds)
                continue

    cipher_text = output.getvalue()

    aes_obj = AES.new(key, AES.MODE_CBC, iv)
    plain_text = aes_obj.decrypt(cipher_text)

    with open(path, 'wb') as file:
        file.write(plain_text)
    print("Saved the decrypted data to", path, "size = ", len(plain_text))

if __name__ == "__main__":
    # With SSR (https://github.com/deislabs/mystikos/blob/main/doc/design/secret-provisioning.md)
    # We expect the following key files exist under root directory: model.key and image.key.
    with open("/model.key", 'rb') as fin:
        key = bytes(fin.read())
        assert(len(key) != 0)
        # Debug only!
        #print("Model key: ", key.hex())

        # Download the encrypted model and decrypt it with the AES key stored in model.key.
        url = 'https://jenkinspublicstorage.blob.core.windows.net/mystikospublicsamples/alexnet-pretrained.pt.encrypted'
        download_and_decrypt(url, "/app/alexnet-pretrained.pt", key)

        print("Created AlexNet instance")
        alexnet = AlexNetInference()

    with open("/image.key", 'rb') as fin:
        image_key = bytes(fin.read())
        assert(len(image_key) != 0)
        # Debug only!
        # print("Image key: ", image_key.hex())

    # Now we are ready to run the web server.
    app.run(debug=True, host="0.0.0.0", port="8000", use_reloader=False)
