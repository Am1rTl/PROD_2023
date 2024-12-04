	FROM python:3.12.1-alpine3.19

WORKDIR /app

RUN mkdir instance

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

RUN chmod +x init_db_fixed.sh
RUN ./init_db_fixed.sh

ENV SERVER_PORT=8080

CMD ["sh", "-c", "exec python3 -m flask run --host=0.0.0.0 --port=$SERVER_PORT"]
