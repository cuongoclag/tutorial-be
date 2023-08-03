import { DataSource } from 'typeorm'

import { SnakeNamingStrategy } from './src/snake-naming.strategy'

dotenv.config()
export const dataSource = new DataSource({
  type: 'mysql',
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  username: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.DB_DATABASE,
  namingStrategy: new SnakeNamingStrategy(),
  entities: ['src/modules/**/*.entity{.ts,.js}', 'src/modules/**/*.view-entity{.ts,.js}'],
  migrations: ['src/database/migrations/*{.ts,.js}']
})
