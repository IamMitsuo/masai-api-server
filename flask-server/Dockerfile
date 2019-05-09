FROM python:3.6.5

ENV APP /app
ENV DOWNLOAD_TEMP_DIR /app/temp/
ENV PDF_REPORT_TEMP_DIRECTORY /app/pdfreport/
ENV LOGO_PATH /app/image/logo.png
ENV TABLE_PATH /app/image/table.jpg
ENV APP_SRC /app/app/

RUN mkdir $APP
WORKDIR $APP

EXPOSE 5000

COPY requirements.txt .

RUN pip install -r requirements.txt && pip install gunicorn

COPY . .

CMD ["gunicorn", "--workers=1", "-b", "0.0.0.0:5000", "app.app:masai_server"]