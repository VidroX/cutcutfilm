import dotenv from 'dotenv';
import { rootDir } from './path_utils.js';
import path from 'path';

dotenv.config({
	path: path.join(rootDir, '..', '.env'),
});

export const LISTEN_IP = process.env.LISTEN_IP ?? '';
export const PORT = process.env.PORT ?? 4000;
export const ENABLE_CORS = (process.env.ENABLE_CORS ?? 'true') === 'true';
export const DEBUG = (process.env.DEBUG ?? 'false') === 'true';
export const NODE_ENV = process.env.NODE_ENV ?? 'production';
export const ENVIRONMENT_TYPE = process.env.ENVIRONMENT_TYPE ?? 'production';

export const IDENTITY_SERVICE_LOCATION = process.env.IDENTITY_SERVICE_LOCATION ?? '';
export const IDENTITY_SERVICE_API_KEY = process.env.IDENTITY_SERVICE_API_KEY ?? '';

export const DATA_LOCATION = process.env.DATA_LOCATION ?? 'data';
export const KEYS_LOCATION = `${DATA_LOCATION}/keys`;
