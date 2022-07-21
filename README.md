Для запуска через docker compose необходимо использовать команды:

```sh
docker-compose up -d --build
docker-compose exec ylab_app alembic upgrade head 
```


Документация находится по адресу:

http://127.0.0.1:8000/api/openapigi