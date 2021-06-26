# spring-security-demo

this is a demo for Spring Boot integrates Spring Security

## Usage

docker
```bash
docker run --name my-mysql -e MYSQL_ROOT_PASSWORD=123 -e MYSQL_DATABASE=community -p 3306:3306 -d mysql
```
flyway
```bash
mvn flyway:clean flyway:migrate
```

admin
- username:admin
- password:aaa
- verifyCode:1234

normal user
- username:aaa
- password:aaa
- verifyCode:1234
