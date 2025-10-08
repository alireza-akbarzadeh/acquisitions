import express from 'express';
import { signIn, signOut, signup } from '#controllers/auth.controller.js';

const authRouter = express.Router();

authRouter.post('/sign-up', signup);

authRouter.post('/sign-in', signIn);
authRouter.post('/sign-out', signOut);

export default authRouter;
