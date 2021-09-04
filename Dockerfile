FROM ubuntu:latest
RUN apt-get update -y
RUN apt-get install -y build-essential python3.6  python3-pip curl
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python3"]
CMD ["app.py"]