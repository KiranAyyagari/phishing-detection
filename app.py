import os
import uuid
import logging
from flask import Flask, render_template, request
from forms import AcceptURL
from url_features_extraction import predict

secret_key = uuid.uuid4().hex
logging.Formatter('%(asctime)s : %(levelname)s : %(name)s : %(message)s')
logger = logging.getLogger(__name__)
app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key


@app.route("/", methods=['GET', 'POST'])
@app.route("/predict", methods=['GET', 'POST'])
def predict_url():
    prediction = ""
    form = AcceptURL()
    if request.method == "POST" and \
            form.validate_on_submit():
        u = form.url.data
        form.url.data = ""
        p = predict(u)
        p = int(p[0])
        if p == 1:
            prediction = "Legitimate Website"
            logger.info("Url is Legitimate")
        else:
            prediction = "Phishing Website"
            logger.info("Url is Phishing")
    else:
        form.url.data = ""
        return render_template("index.html", prediction_text="", form=form)
    return render_template("index.html", prediction_text=prediction, form=form)


if __name__ == "__main__":
    port = os.environ.get("PORT", 5000)
    app.run(debug=True, host='0.0.0.0', port=port)
