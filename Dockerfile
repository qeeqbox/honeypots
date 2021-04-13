FROM python:3.6
COPY . /app
WORKDIR /app
RUN pip3 install .
CMD /bin/bash