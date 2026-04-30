import { defineConfig } from 'prisma/config';
import 'dotenv/config';
console.log('DB URL IS: ', process.env.DATABASE_URL);
export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: {
    url: process.env.DATABASE_URL || 'file:./dev.db',
  },
});
