    FROM python:3.14-slim



    #Add non root user for container to run with
    RUN useradd app

    WORKDIR /app

    #Installing Dependencies
    COPY requirements.txt ./
    RUN pip install --no-cache-dir -r requirements.txt

    #Copy alembic migrations
    COPY alembic ./alembic
    COPY alembic.ini ./

    #Copy source code
    COPY --chown=app:app app ./app

    #Run as non root user
    EXPOSE 8000

    USER app
    CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]




