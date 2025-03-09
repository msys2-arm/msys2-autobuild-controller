FROM python:3.13-bookworm

RUN python -m pip install "poetry==2.1.1"

COPY . /app
WORKDIR /app
RUN poetry config virtualenvs.in-project true
RUN poetry install --only main

ENTRYPOINT ["poetry", "run", "gunicorn", "-w", "2", "--access-logfile", "-", "--bind", "0.0.0.0:80", "flask_app:app"]

EXPOSE 80
