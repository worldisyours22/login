import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

// @note starter items configuration
interface StarterItemsConfig {
  items: Array<{ itemId: number; count: number }>;
  startingCurrency: {
    gems: number;
    coins: number;
  };
  unlockedAchievements: string[];
}

// @note load starter items configuration
function loadStarterItems(): StarterItemsConfig {
  try {
    const starterItemsPath = path.join(process.cwd(), 'starter-items.json');
    if (fs.existsSync(starterItemsPath)) {
      const data = fs.readFileSync(starterItemsPath, 'utf-8');
      return JSON.parse(data) as StarterItemsConfig;
    }
  } catch (error) {
    console.error('[WARN] Failed to load starter items, using defaults:', error);
  }
  
  // Default starter items
  return {
    items: [
      { itemId: 2, count: 100 },
      { itemId: 4, count: 50 },
      { itemId: 8, count: 10 },
      { itemId: 14, count: 1 },
      { itemId: 18, count: 1 },
      { itemId: 242, count: 100 }
    ],
    startingCurrency: {
      gems: 100,
      coins: 0
    },
    unlockedAchievements: ['first_login', 'started_journey']
  };
}

const app = express();
const PORT = 3000;

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

// @note paths configuration
const DATABASE_PATH = path.join(process.cwd(), '..', 'database', 'players');

// @note request logging middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log('[REQ] ' + req.method + ' ' + req.path + ' -> ' + clientIp);
  next();
});

// @note PlayerData interface - matches C++ Player struct
interface PlayerData {
  tankIDName: string;              // Username field (matches C++ Player struct)
  tankIDPass: string;               // Password field (matches C++ Player struct)
  email?: string;
  inventory: Array<[number, number]>;  // vector<pair<int, int>> format
  achievements: Record<string, number>; // map<string, int> format
  last_world: string;               // Top-level field for last world
  x: number;                        // Top-level field for x position
  y: number;                        // Top-level field for y position
  created_at?: string;
  growid?: string;
  is_guest?: boolean;
  gems: number;                     // Required field
  coins?: number;
  flag: number;                     // Player flag field
  country: string;                  // Country field
  mac?: string;                     // MAC address
  rid?: string;                     // RID field
  gateId?: number;                  // Gate ID field
  platforms: Array<[number, number, number]>; // Platforms data
}

// @note guest player data interface - temporary session with limited access
interface GuestPlayerData extends PlayerData {
  is_guest: true;
  guest_id: string;
  session_expires_at: string;
}
function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// @note helper function to verify passwords
function verifyPassword(password: string, hash: string): boolean {
  return hashPassword(password) === hash;
}

// @note helper function to generate session token - URL-encoded format for C++ server
function generateSessionToken(tankIDName: string, growid?: string): string {
  const timestamp = Date.now().toString();
  const _token = crypto.randomBytes(16).toString('hex');
  const growid_val = growid || tankIDName;
  // Use URL-encoded format: _token=<value>&growId=<value>&timestamp=<value>
  const data = `_token=${_token}&growId=${growid_val}&timestamp=${timestamp}`;
  return Buffer.from(data).toString('base64');
}

// @note helper function to decode token - handles URL-encoded format
function decodeToken(token: string): { tankIDName: string; growid: string; timestamp: string; _token: string; is_guest?: boolean } | null {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    // Try to parse as URL-encoded format first
    if (decoded.includes('=') && decoded.includes('&')) {
      const params = new URLSearchParams(decoded);
      return {
        tankIDName: params.get('growId') || '',
        growid: params.get('growId') || '',
        timestamp: params.get('timestamp') || '',
        _token: params.get('_token') || '',
        is_guest: params.get('is_guest') === 'true' ? true : undefined
      };
    }
    // Fallback to JSON format for backward compatibility
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

// @note helper function to normalize username (lowercase)
function normalizeUsername(username: string): string {
  return username.toLowerCase();
}

// @note helper function to check if username exists (case-insensitive)
function usernameExists(username: string): boolean {
  const normalizedUsername = normalizeUsername(username);
  
  // Check exact match (already lowercase)
  const exactPath = path.join(DATABASE_PATH, normalizedUsername + '_.json');
  if (fs.existsSync(exactPath)) {
    return true;
  }
  
  // Check for username with trailing numbers (case-insensitive)
  // e.g., if registering "fake", check for "fake1", "Fake1", etc.
  const files = fs.readdirSync(DATABASE_PATH).filter((f: string) => f.endsWith('_.json'));
  for (const file of files) {
    const existingUsername = file.replace('_.json', '').toLowerCase();
    
    // Check if existing username starts with the normalized username and has numbers appended
    if (existingUsername.startsWith(normalizedUsername)) {
      const suffix = existingUsername.slice(normalizedUsername.length);
      // If suffix exists and is all digits, it's a duplicate with trailing numbers
      if (suffix.length > 0 && /^\d+$/.test(suffix)) {
        return true;
      }
    }
  }
  
  return false;
}

// @note helper function to generate guest session token - URL-encoded format
function generateGuestSessionToken(tankIDName: string, guestId: string): string {
  const timestamp = Date.now().toString();
  const expirationTime = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours
  const _token = crypto.randomBytes(16).toString('hex');
  // Use URL-encoded format with guest-specific fields
  const data = `_token=${_token}&growId=${tankIDName}&timestamp=${timestamp}&is_guest=true&guest_id=${guestId}&session_expires_at=${expirationTime}`;
  return Buffer.from(data).toString('base64');
}

// @note helper function to create guest player data - matches C++ Player struct
function createGuestPlayerData(tankIDName: string, guestId: string): GuestPlayerData {
  const expirationTime = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours
  const starterItems = loadStarterItems();
  
  return {
    tankIDName,
    tankIDPass: '', // No password for guests
    is_guest: true as const,
    guest_id: guestId,
    session_expires_at: expirationTime,
    inventory: starterItems.items.map(item => [item.itemId, item.count] as [number, number]),
    achievements: {},
    last_world: 'START',
    x: 100,
    y: 100,
    created_at: new Date().toISOString(),
    growid: tankIDName,
    gems: starterItems.startingCurrency.gems,
    coins: starterItems.startingCurrency.coins,
    flag: 0,
    country: 'US',
    mac: '',
    rid: '',
    gateId: 0,
    platforms: [],
  };
}

// @note helper function to create default player data with starter items - matches C++ Player struct
function createDefaultPlayerData(tankIDName: string, passwordHash: string, email: string = ''): PlayerData {
  const starterItems = loadStarterItems();
  
  return {
    tankIDName: tankIDName,
    tankIDPass: passwordHash,
    email,
    inventory: starterItems.items.map(item => [item.itemId, item.count] as [number, number]),
    achievements: {
      gems_collected: starterItems.startingCurrency.gems,
      blocks_broken: 0,
      blocks_placed: 0
    },
    last_world: 'START',
    x: 100,
    y: 100,
    created_at: new Date().toISOString(),
    growid: tankIDName,
    gems: starterItems.startingCurrency.gems,
    coins: starterItems.startingCurrency.coins,
    flag: 0,
    country: 'US',
    mac: '',
    rid: '',
    gateId: 0,
    platforms: [],
  };
}

// @note helper function to generate unique guest username
function generateGuestUsername(): string {
  const randomId = crypto.randomBytes(4).toString('hex');
  return 'Guest_' + randomId;
}

// @note helper function to read player data
function readPlayerData(username: string): PlayerData | null {
  const normalizedUsername = normalizeUsername(username);
  const filePath = path.join(DATABASE_PATH, normalizedUsername + '_.json');
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data) as PlayerData;
  } catch (error) {
    console.error('[ERROR] Failed to read player data for ' + username + ':', error);
    return null;
  }
}

// @note helper function to write player data
function writePlayerData(username: string, data: PlayerData): boolean {
  const normalizedUsername = normalizeUsername(username);
  const filePath = path.join(DATABASE_PATH, normalizedUsername + '_.json');
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('[ERROR] Failed to write player data for ' + username + ':', error);
    return false;
  }
}

// @note root endpoint
app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

/**
 * @note dashboard endpoint - serves login HTML page with client data
 * @param req - express request with optional body data
 * @param res - express response
 */
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
      console.log('[ERROR]: ' + why);
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
  
  // @note replace placeholders for login mode (isRegister = false)
  let htmlContent = templateContent
    .replace('__TOKEN__', tDataBase64)
    .replace('__IS_REGISTER__', 'false')
    .replace('__TAB_HIDDEN__', '')
    .replace('__LOGIN_TAB_CLASS__', 'tab-active')
    .replace('__REGISTER_TAB_CLASS__', 'tab-inactive')
    .replace('__LOGIN_CLASS__', '')
    .replace('__REGISTER_CLASS__', 'form-hidden opacity-0 translate-y-[-20px]');

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

/**
 * @note registration page endpoint - serves registration HTML page
 * @param req - express request
 * @param res - express response
 */
app.get('/player/register', async (req: Request, res: Response) => {
  const tData: Record<string, string> = {};
  const tDataBase64 = Buffer.from(JSON.stringify(tData)).toString('base64');

  // @note read dashboard template
  const templatePath = path.join(
    process.cwd(),
    'template',
    'dashboard.html',
  );

  const templateContent = fs.readFileSync(templatePath, 'utf-8');
  
  // @note replace placeholders for register mode (isRegister = true)
  let htmlContent = templateContent
    .replace('__TOKEN__', tDataBase64)
    .replace('__IS_REGISTER__', 'true')
    .replace('__TAB_HIDDEN__', 'hidden')
    .replace('__LOGIN_TAB_CLASS__', 'tab-inactive')
    .replace('__REGISTER_TAB_CLASS__', 'tab-active')
    .replace('__LOGIN_CLASS__', 'form-hidden opacity-0 translate-y-[-20px]')
    .replace('__REGISTER_CLASS__', '');

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

/**
 * @note validate login endpoint - validates GrowID credentials against player JSON files
 * @param req - express request with growId, password, _token
 * @param res - express response with token
 */
app.all(
  '/player/growid/login/validate',
  async (req: Request, res: Response) => {
    try {
      const formData = req.body as Record<string, string>;
      const _token = formData._token;
      const growId = formData.growId;
      const password = formData.password;

      // @note validate required fields
      if (!growId || !password) {
        res.status(400).json({
          status: 'error',
          message: 'Missing growId or password',
        });
        return;
      }

      // @note read player data from database (case-insensitive lookup)
      const playerData = readPlayerData(growId);

      if (!playerData) {
        res.status(401).json({
          status: 'error',
          message: 'Invalid credentials',
        });
        return;
      }

      // @note verify password
      if (!verifyPassword(password, playerData.tankIDPass)) {
        res.status(401).json({
          status: 'error',
          message: 'Invalid credentials',
        });
        return;
      }

      // @note generate session token
      const sessionToken = generateSessionToken(playerData.tankIDName, playerData.growid);

      // @note create token with base64 encoding as expected by client (URL-encoded format)
      const token = Buffer.from(
        '_token=' + sessionToken + '&growId=' + growId + '&password=' + playerData.tankIDPass + '&reg=0',
      ).toString('base64');

      res.setHeader('Content-Type', 'text/html');
      res.json({
        status: 'success',
        message: 'Account Validated.',
        token,
        url: '',
        accountType: 'growtopia',
      });
    } catch (error) {
      console.log('[ERROR]: ' + error);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  },
);

/**
 * @note registration endpoint - register new player with username, password, email
 * @param req - express request with username, password, email
 * @param res - express response with token
 */
app.all(
  '/player/growid/register',
  async (req: Request, res: Response) => {
    try {
      const formData = req.body as Record<string, string>;
      const username = formData.username || formData.growId;
      const password = formData.password;
      const email = formData.email || '';

      // @note validate required fields
      if (!username || !password) {
        res.status(400).json({
          status: 'error',
          message: 'Missing username or password',
        });
        return;
      }

      // @note validate username format
      if (username.length < 3 || username.length > 20) {
        res.status(400).json({
          status: 'error',
          message: 'Username must be between 3 and 20 characters',
        });
        return;
      }

      // @note validate password length
      if (password.length < 6) {
        res.status(400).json({
          status: 'error',
          message: 'Password must be at least 6 characters',
        });
        return;
      }

      // @note check if player already exists (case-insensitive)
      if (usernameExists(username)) {
        res.status(409).json({
          status: 'error',
          message: 'Username already exists',
        });
        return;
      }

      // @note normalize username for storage
      const normalizedUsername = normalizeUsername(username);

      // @note create new player data structure with starter items
      const newPlayerData = createDefaultPlayerData(normalizedUsername, hashPassword(password), email);

      // @note write player data to database
      const writeSuccess = writePlayerData(normalizedUsername, newPlayerData);
      if (!writeSuccess) {
        res.status(500).json({
          status: 'error',
          message: 'Failed to create account',
        });
        return;
      }

      // @note generate session token for new player
      const sessionToken = generateSessionToken(normalizedUsername, normalizedUsername);

      // @note create token with base64 encoding (URL-encoded format for C++ server)
      const token = Buffer.from(
        '_token=' + sessionToken + '&growId=' + normalizedUsername + '&password=' + newPlayerData.tankIDPass + '&reg=1',
      ).toString('base64');

      res.json({
        status: 'success',
        message: 'Account created successfully.',
        token,
        url: '',
        accountType: 'growtopia',
      });
    } catch (error) {
      console.log('[ERROR]: ' + error);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  },
);

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

      // @note decode and validate the refresh token
      const decodedToken = decodeToken(refreshToken);
      if (!decodedToken) {
        res.status(401).json({
          status: 'error',
          message: 'Invalid token format',
        });
        return;
      }

      // @note verify the player still exists
      const playerData = readPlayerData(decodedToken.growid);
      if (!playerData) {
        res.status(401).json({
          status: 'error',
          message: 'Player not found',
        });
        return;
      }

      let decodeRefreshToken = Buffer.from(refreshToken, 'base64').toString(
        'utf-8',
      );

      const token = Buffer.from(
        decodeRefreshToken.replace(
          /(_token=)[^&]*/,
          '$1' + Buffer.from(clientData).toString('base64'),
        ),
      ).toString('base64');

      res.send(
        '{"status":"success","message":"Token is valid.","token":"' + token + '","url":"","accountType":"growtopia"}',
      );
    } catch (error) {
      console.log('[ERROR]: ' + error);
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
  },
);

/**
 * @note guest login endpoint - creates a temporary guest session without registration
 * @param req - express request (optional device_id for tracking)
 * @param res - express response with guest token
 */
app.all('/player/guest/login', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;
    const deviceId = formData.device_id || formData.mac_address || '';

    // @note generate unique guest username and ID
    const guestUsername = generateGuestUsername();
    const guestId = crypto.randomBytes(8).toString('hex');

    // @note create guest player data
    const guestData = createGuestPlayerData(guestUsername, guestId);

    // @note optionally save guest data to database (optional - guests can be session-only)
    // For this implementation, we'll save it to allow session persistence
    const writeSuccess = writePlayerData(guestUsername, guestData);
    if (!writeSuccess) {
      console.log('[WARN] Failed to write guest player data for ' + guestUsername + ', continuing anyway');
    }

    // @note generate guest session token with is_guest flag
    const sessionToken = generateGuestSessionToken(guestUsername, guestId);

    // @note create token with base64 encoding as expected by client
    const token = Buffer.from(
      '_token=' + sessionToken + '&growId=' + guestUsername + '&password=&reg=0&is_guest=true',
    ).toString('base64');

    console.log('[GUEST] New guest session created: ' + guestUsername + ' (' + guestId + ')');

    res.json({
      status: 'success',
      message: 'Guest session created successfully.',
      token,
      url: '',
      accountType: 'guest',
      guest_id: guestId,
      expires_at: guestData.session_expires_at,
    });
  } catch (error) {
    console.log('[ERROR]: ' + error);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

app.listen(PORT, () => {
  console.log('[SERVER] Running on http://localhost:' + PORT);
  console.log('[SERVER] Database path: ' + DATABASE_PATH);
});

export default app;
