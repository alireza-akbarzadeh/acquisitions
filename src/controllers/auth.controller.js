import logger from '#config/logger.js';
import { MESSAGE } from '#constants/messages.js';
import { ERROR_MESSAGE } from '#constants/errors.ts.js';
import { HTTP_STATUS } from '#constants/http.js';
import { signInSchema, signUpSchema } from '#validations/auth-validation.js';
import { formatValidationError } from '#utils/format.js';
import { authenticateUser, createUser } from '#services/auth.service.js';
import { jwttoken } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js';

export const signup = async (req, res, next) => {
  try {
    const validationResult = signUpSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: ERROR_MESSAGE.VALIDATION_FAILED,
        details: formatValidationError(validationResult.error),
        message: validationResult.error.message,
      });
    }
    const { name, email, role, password } = validationResult.data;
    const user = await createUser({ name, email, password, role });
    const token = jwttoken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });
    cookies.setValue(res, 'token', token);

    logger.info(MESSAGE.USER_REGISTER_SUCCESSFULLY + ' ' + email);
    res.status(HTTP_STATUS.CREATED).json({
      message: MESSAGE.USER_REGISTERED,
      user: {
        email: user.email,
        name: user.name,
        role: user.role,
        id: user.id,
      },
    });
  } catch (error) {
    logger.error('signup error', error);
    if (error.message === MESSAGE.EMAIL_ALREADY_EXISTS) {
      return res
        .status(HTTP_STATUS.CONFLICT)
        .json({ message: ERROR_MESSAGE.EMAIL_ALREADY_EXISTS });
    }
    next(error);
  }
};

export const signIn = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        error: ERROR_MESSAGE.VALIDATION_FAILED,
        details: formatValidationError(validationResult.error),
      });
    }

    const { email, password } = validationResult.data;

    const user = await authenticateUser({ email, password });

    const token = jwttoken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    cookies.setValue(res, 'token', token);

    logger.info(`User signed in successfully: ${email}`);
    res.status(HTTP_STATUS.OK).json({
      message: MESSAGE.USER_REGISTER_SUCCESSFULLY,
      user: {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      },
    });
  } catch (e) {
    logger.error('Sign in error', e);

    if (e.message === 'User not found' || e.message === 'Invalid password') {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    next(e);
  }
};

export const signOut = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');

    res.status(HTTP_STATUS.OK).json({
      message: MESSAGE.USER_REGISTER_SUCCESSFULLY,
    });
  } catch (e) {
    logger.error('Sign out error', e);
    next(e);
  }
};
