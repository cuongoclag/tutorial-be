Link diagram: https://dbdiagram.io/d/64b8fe5202bd1c4a5e661759

Step by Step for run backend 

- Create MySql with docker
(
- run : docker pull mysql with terminal
- run : docker run --name tutorial -e MYSQL_ROOT_PASSWORD=root -p 3060:3060 mysql:tag

) 

- clone source (git pull "your link")
- yarn install
- Update file .env for the same config database (name or password, port)
- yarn run start:dev



