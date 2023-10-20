FROM python:3.11.6-alpine3.18

COPY src/ .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 18018/tcp

CMD [ "python", "main.py" ]