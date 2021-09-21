# Phishing-Detection:
This project is to verify Url is phishing or not using Machine Learning

# Problem Statement:  
    Phishing is a type of fraud in which an attacker impersonates a reputable company or 
    person in order to get sensitive information such as login credentials or account 
    information via email or other communication channels. Phishing is popular among 
    attackers because it is easier to persuade someone to click a malicious link that 
    appears to be authentic than it is to break through a computer's protection measures.
    The mail goal is to predict whether the domains are real or malicious. 

# Solution:
    1.Train the dataset which is provided by - https://archive.ics.uci.edu/ml/datasets/phishing+websites
    2.Dataset description can be found in Phishing Websites Features.docx file in Documents folder
    3.Data is trained using different models like Random Forest,XGBoost, SVM etc
    4.Beter accuracy is achieved using SVM model
    3.Extract the features from Url provided to predict whether URL is Phishing or Legitimate website
# Setup
    Create environment using conda for this project 
    conda create -n <envname>
    conda activate <envname>

Install all the packages required for the project

`pip intall -r requirements.txt`

Create .env file and add below configuration

    export OPEN_PAGE_RANK_API_KEY=<APIKEY> 
    export OPEN_PAGE_RANK_URL=https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=
    export PHISHTANK_URL=http://checkurl.phishtank.com/checkurl/

Get your own API key from Page Rank website

Running the app in local environment

`python app.py`

And launch the localhost server - http://192.168.1.2:5000/

# Dockerizing application
    Build docker image 
    docker build -t phishing-detection:latest .
    And run the docker image to check docker image is successful
    docker run -d -p 5000:5000 phishing-detection


# Deploy to heroku
    Login to heroku - heroku login
    Login to container - heroku container:login
    Create heroku app - heroku create <app-name>
    Push app to heroku container - heroku container:push web --app <app-name>
    Release the app - heroku container:release web --app <app-name>
    
My app is deployed in heroku.

Find here-https://detectphishing.herokuapp.com/
