import express from 'express';
import { signup } from '#controllers/auth.controller.js';

const authRouter = express.Router();

authRouter.post('/sign-up', signup);

authRouter.post('/sign-in', (req, res) => {
  res.send('POST /api/auth/sign-in response');
});

authRouter.post('/sign-out', (req, res) => {
  res.send('POST /api/auth/sign-out response');
});

export default authRouter;
