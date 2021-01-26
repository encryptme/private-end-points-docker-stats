FROM python:3.6

WORKDIR /usr/src/app

COPY . /usr/src/app

RUN pip install --no-cache-dir .

CMD [ "encryptme-stats" ]
