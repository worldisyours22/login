import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3000;

// Database path
const DB_PATH = path.join(process.cwd(), '..', '..', 'database', 'players');

// @note trust proxy - set to number of proxies in front of app
app.set('trust proxy', 1);

// @note middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// @note rate limiter - 50 requests per minute
const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

// @note static files from public folder
app.use(express.static(path.join(process.cwd(), 'public')));

// @note request logging middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(
    `[REQ] ${req.method} ${req.path} → ${clientIp} | ${_res.statusCode}`,
  );
  next();
});

// @note root endpoint
app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

// @note helper function to read player database
function readPlayerDatabase(growId: string): any | null {
  try {
    const filePath = path.join(DB_PATH, `${growId}_.json`);
    if (fs.existsSync(filePath)) {
      const data = fs.readFileSync(filePath, 'utf-8');
      return JSON.parse(data);
    }
    return null;
  } catch (error) {
    console.log(`[ERROR] Failed to read player database: ${error}`);
    return null;
  }
}

// @note helper function to write player database
function writePlayerDatabase(growId: string, data: any): boolean {
  try {
    const filePath = path.join(DB_PATH, `${growId}_.json`);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.log(`[ERROR] Failed to write player database: ${error}`);
    return false;
  }
}

// @note check if player exists
function playerExists(growId: string): boolean {
  const filePath = path.join(DB_PATH, `${growId}_.json`);
  return fs.existsSync(filePath);
}

// @note dashboard endpoint - serves login HTML page with client data
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  const tData: Record<string, string> = {};

  // @note handle empty body or missing data
  const body = req.body;
  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    try {
      const bodyStr = JSON.stringify(body);
      const parts = bodyStr.split('"');

      if (parts.length > 1) {
        const uData = parts[1].split('\n');
        for (let i = 0; i < uData.length - 1; i++) {
          const d = uData[i].split('|');
          if (d.length === 2) {
            tData[d[0]] = d[1];
          }
        }
      }
    } catch (why) {
      console.log(`[ERROR]: ${why}`);
    }
  }

  // @note convert tData object to base64 string
  const tDataBase64 = Buffer.from(JSON.stringify(tData)).toString('base64');

  // @note read dashboard template and replace placeholder
  const templatePath = path.join(
    process.cwd(),
    'template',
    'dashboard.html',
  );

  const templateContent = fs.readFileSync(templatePath, 'utf-8');
  const htmlContent = templateContent.replace('{{ data }}', tDataBase64);

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

/**
 * @note validate login endpoint - validates GrowID credentials
 * @param req - express request with growId, password, _token
 * @param res - express response with token
 */
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;
    const _token = formData._token;
    const growId = formData.growId;
    const password = formData.password;

    // @note validate input
    if (!growId || !password) {
      res.setHeader('Content-Type', 'text/html');
      res.status(400).json({
        status: 'error',
        message: 'Username or password is empty',
      });
      return;
    }

    // @note check if player exists
    if (!playerExists(growId)) {
      res.setHeader('Content-Type', 'text/html');
      res.status(401).json({
        status: 'error',
        message: 'Account not found. Please register first.',
      });
      return;
    }

    // @note read player data
    const playerData = readPlayerDatabase(growId);
    if (!playerData) {
      res.setHeader('Content-Type', 'text/html');
      res.status(500).json({
        status: 'error',
        message: 'Failed to read account data',
      });
      return;
    }

    // @note verify password
    if (playerData.pass !== password) {
      res.setHeader('Content-Type', 'text/html');
      res.status(401).json({
        status: 'error',
        message: 'Incorrect password',
      });
      return;
    }

    // @note login successful - return token with server URL
    const serverUrl = process.env.SERVER_URL || '127.0.0.1';
    const serverPort = process.env.SERVER_PORT || '17091';
    
    const token = Buffer.from(
      `_token=${_token}&growId=${growId}&password=${password}&reg=0&server=${serverUrl}:${serverPort}`,
    ).toString('base64');

    res.setHeader('Content-Type', 'text/html');
    res.json({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: `${serverUrl}:${serverPort}`,
      accountType: 'growtopia',
    });
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

/**
 * @note register endpoint - creates a new GrowID account
 * @param req - express request with growId, password, email
 * @param res - express response with status
 */
app.all('/player/growid/register', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;
    const growId = formData.growId;
    const password = formData.password;
    const email = formData.email || '';

    // @note validate input
    if (!growId || !password) {
      res.setHeader('Content-Type', 'text/html');
      res.status(400).json({
        status: 'error',
        message: 'Username and password are required',
      });
      return;
    }

    // @note validate username length
    if (growId.length < 3 || growId.length > 18) {
      res.setHeader('Content-Type', 'text/html');
      res.status(400).json({
        status: 'error',
        message: 'Username must be between 3 and 18 characters',
      });
      return;
    }

    // @note validate password length
    if (password.length < 4 || password.length > 18) {
      res.setHeader('Content-Type', 'text/html');
      res.status(400).json({
        status: 'error',
        message: 'Password must be between 4 and 18 characters',
      });
      return;
    }

    // @note validate username format (alphanumeric only)
    if (!/^[a-zA-Z0-9]+$/.test(growId)) {
      res.setHeader('Content-Type', 'text/html');
      res.status(400).json({
        status: 'error',
        message: 'Username can only contain letters and numbers',
      });
      return;
    }

    // @note check if player already exists
    if (playerExists(growId)) {
      res.setHeader('Content-Type', 'text/html');
      res.status(409).json({
        status: 'error',
        message: 'Username is already taken',
      });
      return;
    }

    // @note create new player data
    const newPlayerData = {
      name: growId,
      pass: password,
      email: email,
      created: Math.floor(Date.now() / 1000),
      gems: 0,
      lvl: 1,
      exp: 0,
      world: 'START',
      inventory: [
        { id: 18, count: 1 },  // Growtoken
        { id: 32, count: 1 },  // World Lock
      ],
      skin: 0,
      hair: 0,
      shirt: 0,
      pants: 0,
      shoes: 0,
      hand: 0,
      back: 0,
      mask: 0,
      necklace: 0,
      ances: 0,
      flag: 0,
      role: {
        vip: false,
        moderator: false,
        administrator: false,
        developer: false,
        owner: false,
      },
      stats: {
        punches: 0,
        place: 0,
        break: 0,
        transactions: 0,
      },
      friends: [],
      worlds: [],
      ip: req.ip || 'unknown',
    };

    // @note write player data to database
    if (!writePlayerDatabase(growId, newPlayerData)) {
      res.setHeader('Content-Type', 'text/html');
      res.status(500).json({
        status: 'error',
        message: 'Failed to create account',
      });
      return;
    }

    console.log(`[INFO] New account created: ${growId}`);

    res.setHeader('Content-Type', 'text/html');
    res.json({
      status: 'success',
      message: 'Account created successfully! Please login.',
      redirect: '/player/login/dashboard',
    });
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

/**
 * @note first checktoken endpoint - redirects using 307 to preserve data
 * @param req - express request with refreshToken and clientData
 * @param res - express response with updated token
 */
app.all('/player/growid/checktoken', async (req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

/**
 * @note second checktoken endpoint - validates token and returns updated token
 * @param req - express request with refreshToken and clientData
 * @param res - express response with updated token
 */
app.all(
  '/player/growid/validate/checktoken',
  async (req: Request, res: Response) => {
    try {
      // @note handle both { data: { ... } } and { refreshToken, clientData } formats
      const body = req.body as
        | { data: { refreshToken: string; clientData: string } }
        | { refreshToken: string; clientData: string };

      const refreshToken =
        'data' in body ? body.data?.refreshToken : body.refreshToken;
      const clientData =
        'data' in body ? body.data?.clientData : body.clientData;

      if (!refreshToken || !clientData) {
        res.status(400).json({
          status: 'error',
          message: 'Missing refreshToken or clientData',
        });
        return;
      }

      let decodeRefreshToken = Buffer.from(refreshToken, 'base64').toString(
        'utf-8',
      );

      const token = Buffer.from(
        decodeRefreshToken.replace(
          /(_token=)[^&]*/,
          `$1${Buffer.from(clientData).toString('base64')}`,
        ),
      ).toString('base64');

      res.send(
        `{"status":"success","message":"Token is valid.","token":"${token}","url":"","accountType":"growtopia"}`,
      );
    } catch (error) {
      console.log(`[ERROR]: ${error}`);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  },
);

/**
 * @note API endpoint to check if username is available
 */
app.all('/player/growid/checkavailable', async (req: Request, res: Response) => {
  try {
    const growId = req.body.growId as string;
    
    if (!growId || growId.length < 3 || growId.length > 18) {
      res.json({ available: false, message: 'Username must be 3-18 characters' });
      return;
    }

    if (!/^[a-zA-Z0-9]+$/.test(growId)) {
      res.json({ available: false, message: 'Username can only contain letters and numbers' });
      return;
    }

    const exists = playerExists(growId);
    res.json({ available: !exists, message: exists ? 'Username taken' : 'Username available' });
  } catch (error) {
    console.log(`[ERROR]: ${error}`);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
  console.log(`[DB] Player database path: ${DB_PATH}`);
});

export default app;
