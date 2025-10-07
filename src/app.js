import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import logger from '#config/logger.js';
import authRoutes from '#routes/auth.routes.js';
import { HTTP_STATUS } from '#constants/http.js';

const app = express();

app.use(helmet());
app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  morgan('combined', {
    stream: { write: message => logger.info(message.trim()) },
  })
);

app.get('/', (req, res) => {
  logger.info('Hello World Acquisitions!');
  res.status(HTTP_STATUS.OK).send('Hello World Acquisitions!');
});

app.get('/health', (req, res) => {
  res.status(HTTP_STATUS.OK).json({
    status: 'OK',
    time: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.get('/api', (req, res) => {
  res.status(HTTP_STATUS.OK).json({ message: 'Acquisitions API is Running!' });
});

app.use('/api/auth', authRoutes);

export default app;
