FROM python:alpine3.7

COPY . .
RUN pip install -r requirements.txt

CMD [ "python", "check.py" ]