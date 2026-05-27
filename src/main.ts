// src/main.ts
import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // ⭐ QUAN TRỌNG: Chỉ list origin 1 LẦN, không duplicate
  const allowedOrigins = [
    'https://ecommerce-frontend-demo-wi-fa-key.vercel.app',
    'http://localhost:3001',
  ];

  // ⭐ Dùng string thay vì function để tránh duplicate
  app.enableCors({
    origin: allowedOrigins, // Đơn giản hơn, không dùng callback
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'ngrok-skip-browser-warning',
    ],
    credentials: false,
    preflightContinue: false,
    optionsSuccessStatus: 204,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  app.setGlobalPrefix('api');

  const port = configService.get('port') || 8000;
  await app.listen(port);

  logger.log(`✅ Application running on: http://localhost:${port}`);
  logger.log(`✅ CORS enabled for: ${allowedOrigins.join(', ')}`);
}
bootstrap();
