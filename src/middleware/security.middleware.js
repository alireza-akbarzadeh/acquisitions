import aj from '#config/arcjet.js';
import logger from '#config/logger.js';
import { slidingWindow } from '@arcjet/node';
import { HTTP_STATUS } from '#constants/http.js';
import { ERROR_MESSAGE } from '#constants/errors.ts.js';

export const SECURITY_CONFIG = {
  DEFAULT_INTERVAL: '1m',
  DEFAULT_MODE: 'LIVE',

  ROLES: {
    admin: {
      limit: 20,
      interval: '1m',
    },
    user: {
      limit: 10,
      interval: '1m',
    },
    guest: {
      limit: 5,
      interval: '1m',
    },
  },
};

const securityMiddleware = async (req, res, next) => {
  try {
    const role = req.user?.role || 'guest';
    const roleConfig =
      SECURITY_CONFIG.ROLES[role] || SECURITY_CONFIG.ROLES.guest;

    const client = aj.withRule(
      slidingWindow({
        mode: SECURITY_CONFIG.DEFAULT_MODE,
        interval: roleConfig.interval || SECURITY_CONFIG.DEFAULT_INTERVAL,
        max: roleConfig.limit,
        name: `${role}-rate-limit`,
      })
    );

    const decision = await client.protect(req);

    // Handle blocked bots
    if (decision.isDenied() && decision.reason.isBot()) {
      logger.warn('Bot request blocked', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
      });

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        error: ERROR_MESSAGE.ARCJET_ERROR,
        message: ERROR_MESSAGE.FORBIDDEN_BOT,
      });
    }

    // Handle shield blocks
    if (decision.isDenied() && decision.reason.isShield()) {
      logger.warn('Shield blocked request', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
      });

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        error: ERROR_MESSAGE.ARCJET_ERROR,
        message: ERROR_MESSAGE.FORBIDDEN_SHIELD,
      });
    }

    // Handle rate limit exceed
    if (decision.isDenied() && decision.reason.isRateLimit()) {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
      });

      return res.status(HTTP_STATUS.FORBIDDEN).json({
        error: ERROR_MESSAGE.ARCJET_ERROR,
        message: ERROR_MESSAGE.FORBIDDEN_RATE_LIMIT,
      });
    }

    next();
  } catch (e) {
    logger.error('Arcjet middleware error:', {
      error: e.message,
      stack: e.stack,
    });

    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      error: ERROR_MESSAGE.ARCJET_ERROR,
      message: ERROR_MESSAGE.INTERNAL_ERROR,
    });
  }
};

export default securityMiddleware;
