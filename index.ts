import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

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
app.all(
  '/player/growid/login/validate',
  async (req: Request, res: Response) => {
    try {
      const formData = req.body as Record<string, string>;
      const _token = formData._token;
      const growId = formData.growId;
      const password = formData.password;

      const token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&reg=0`,
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
      console.log(`[ERROR]: ${error}`);
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

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
