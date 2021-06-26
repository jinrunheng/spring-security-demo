# spring-security-demo

this is a demo for Spring Boot integrates Spring Security

## Usage

use docker start mysql service
```bash
docker run --name my-mysql -e MYSQL_ROOT_PASSWORD=123 -e MYSQL_DATABASE=community -p 3306:3306 -d mysql
```
use flyway migration init DB and data
```bash
mvn flyway:clean flyway:migrate
```
you can log in with two kinds of authorities

- Authority

    - ADMIN
        - username:admin
        - password:aaa
        - verifyCode:1234
    - USER    
        - username:aaa
        - password:aaa
        - verifyCode:1234


