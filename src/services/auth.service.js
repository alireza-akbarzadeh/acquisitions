import { ERROR_MESSAGE } from '#constants/errors.ts.js';
import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { eq } from 'drizzle-orm';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import { signUpSchema } from '#validations/auth-validation.js';

export const comparePassword = async (password, hash) => {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    logger.error(ERROR_MESSAGE.COMPARE_PASSWORD_ERROR, error);
    throw new Error(ERROR_MESSAGE.COMPARE_PASSWORD_ERROR);
  }
};

export const hashPassword = async password => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (error) {
    logger.error(ERROR_MESSAGE.HASHING_PASSWORD_ERROR, error);
    throw new Error(ERROR_MESSAGE.HASHING_PASSWORD_ERROR);
  }
};

export const createUser = async ({ name, email, password, role = 'user' }) => {
  try {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existingUser.length > 0)
      throw new Error('User with this email already exists');

    const password_hash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({ name, email, password: password_hash, role })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
      });

    logger.info(`User ${newUser.email} created successfully`);
    return newUser;
  } catch (e) {
    logger.error(`Error creating the user: ${e}`);
    throw e;
  }
};

export const authenticateUser = async ({ email, password }) => {
  try {
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!existingUser) {
      throw new Error('Invalid credentials');
    }

    const isPasswordValid = await comparePassword(
      password,
      existingUser.password
    );

    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    logger.info(`User ${existingUser.email} authenticated successfully`);
    return {
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      role: existingUser.role,
      created_at: existingUser.created_at,
    };
  } catch (e) {
    logger.error(`Error authenticating user: ${e}`);
    throw e;
  }
};
