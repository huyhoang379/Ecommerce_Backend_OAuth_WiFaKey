// src/main.ts
import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // CORS
  app.enableCors({
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    origin: configService.get('frontend_url'),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Global prefix
  app.setGlobalPrefix('api');

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const port = configService.get('port');
  await app.listen(port);

  logger.log(`Application is running on: http://localhost:${port}`);
  logger.log(`Frontend URL: ${configService.get('frontend_url')}`);
}
bootstrap();
