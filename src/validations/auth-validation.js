import { z } from 'zod';

export const signUpSchema = z.object({
  name: z.string().trim().min(3).max(255),
  email: z.email().max(255).toLowerCase().trim(),
  password: z.string().min(6).max(12),
  role: z.enum(['user', 'admin']).default('user'),
});

export const signInSchema = z.object({
  email: z.email().max(255).toLowerCase().trim(),
  password: z.string().min(1),
});
