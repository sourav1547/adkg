If you want to use docker-compose:
1. docker-compose build honeybadgermpc
2. docker-compose run -p 5678:5678 honeybadgermpc pytest tests/test_adkg.py 
3. docker-compose run honeybadgermpc -it

4. docker build -t honeybadger . --build-arg BUILD=dev