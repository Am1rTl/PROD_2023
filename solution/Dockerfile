FROM python:3.12.1-alpine3.19


WORKDIR /app

COPY init_db_fixed.sh init_db_fixed.sh
RUN apk add --no-cache sqlite sqlite-dev
RUN chmod +x init_db_fixed.sh
RUN ls /app
RUN sh init_db_fixed.sh

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

ENV SERVER_PORT=8080

CMD ["sh", "-c", "exec python3 -m flask run --host=0.0.0.0 --port=$SERVER_PORT"]
