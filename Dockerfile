FROM python:3.14-alpine

LABEL VERSION=1.0
LABEL DESCRIPCION="Test Server HTTP V1.0"

ENV HOST_BD ''
ENV USER_BD ''
ENV PASS_BD ''

ENV FLASK_APP app

RUN adduser -h /home/jonnattan -u 10100 -g 10101 --disabled-password jonnattan

COPY ./requirements.txt /home/jonnattan/requirements.txt

RUN cd /home/jonnattan && \
    mkdir -p /home/jonnattan/.local/bin && \
    export PATH=$PATH:/home/jonnattan/.local/bin && \
    pip install --upgrade pip && \
    pip install -r requirements.txt && \
    chmod -R 755 /home/jonnattan  && \
    chown -R jonnattan:jonnattan /home/jonnattan

WORKDIR /home/jonnattan/app

USER jonnattan

EXPOSE 8079

CMD [ "python", "server.py", "8079"]

# CMD [ "tail", "-f", "/home/jonnattan/requirements.txt" ]
# pip freeze > requirements.txt
