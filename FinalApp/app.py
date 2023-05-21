#importing required libraries

from flask import Flask, request, render_template, redirect, url_for
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
import os
import re
import datetime
import shutil
import csv
import cv2
from datetime import datetime
import pyzbar.pyzbar as pyzbar
from pyzbar.pyzbar import decode
from werkzeug.utils import secure_filename
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

file = open("pickle/model.pkl","rb")
gbc = pickle.load(file)
file.close()


app = Flask(__name__)

@app.route("/", methods=["GET","POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        regex=r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        extracted_url=re.findall(regex,url)
        final_url = ''.join([x[0] for x in extracted_url])
        if final_url.startswith("http:") or final_url.startswith("www.") or final_url.startswith("https:"):
          obj = FeatureExtraction(final_url)
          x = np.array(obj.getFeaturesList()).reshape(1,30) 
          y_pred =gbc.predict(x)[0]
          #1 is safe       
          #-1 is unsafe
          y_pro_phishing = gbc.predict_proba(x)[0,0]
          y_pro_non_phishing = gbc.predict_proba(x)[0,1]
          result = "Safe" if y_pred == 1 else "Unsafe"
          save_to_csv(final_url, result,y_pred,y_pro_phishing,y_pro_non_phishing) 
          pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
          return render_template('index.html',xx =round(y_pro_non_phishing,2),url=final_url )
        else:
          return "Invalid URL  ¯\_(ツ)_/¯ "

    else:
        decoded_text = request.args.get('decoded_text')
        regex=r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        decoded_url=re.findall(regex,str(decoded_text))
        final_url = ''.join([x[0] for x in decoded_url])
        if final_url.startswith("http:") or final_url.startswith("www.") or final_url.startswith("https:"):
            obj = FeatureExtraction(final_url)
            x = np.array(obj.getFeaturesList()).reshape(1,30) 
            y_pred = gbc.predict(x)[0]
            #1 is safe       
            #-1 is unsafe
            y_pro_phishing = gbc.predict_proba(x)[0,0]
            y_pro_non_phishing = gbc.predict_proba(x)[0,1]
            result = "Safe" if y_pred == 1 else "Unsafe"
            save_to_csv(final_url, result,y_pred,y_pro_phishing,y_pro_non_phishing)
            # if(y_pred ==1 ):
            pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
            return render_template('index.html',xx =round(y_pro_non_phishing,2),url=final_url )
        else:
            return render_template("index.html", xx =-1)
        
@app.route("/decode_qr", methods=["POST"])
def decode_qr():
    image_path = "static/files/1.png"
    image = cv2.imread(image_path)
    decoded_text = ""
    # Decode QR code in the image
    decoded_objs = pyzbar.decode(image)
    for obj in decoded_objs:
        decoded_text += obj.data.decode("utf-8")
    return redirect(url_for('index',decoded_text=decoded_text))

@app.route('/upload', methods=['POST','GET'])
def upload_file():
    uplfl="images_upl/"
    desfl="static/files/"
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    uploaded_file.save(os.path.join(uplfl, filename))
    newname="1.png"
    shutil.copyfile(os.path.join(uplfl, filename), os.path.join(desfl, newname))

    return "Image uploaded"

def save_to_csv(url, result,y_pred,y_pro_phishing,y_pro_non_phishing):
    with open('results.csv', mode='a') as csv_file:
        fieldnames = ['url', 'result', 'Prediction','Phishing probability','Non-Phishing probability','date']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writerow({'url': url, 'result': result,'Prediction':y_pred,'Phishing probability':y_pro_phishing,'Non-Phishing probability':y_pro_non_phishing,'date': datetime.now()})


if __name__ == "__main__":
    app.run(debug=True)